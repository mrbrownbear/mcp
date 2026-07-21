<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace Novamira\OAuth\Middleware;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Novamira\OAuth\Bridge;
use Novamira\OAuth\ServerFactory;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

if (!defined('ABSPATH') && PHP_SAPI !== 'cli') {
    exit();
}

function register(): void
{
    // WordPress cookie and Application Password authenticators run first. Novamira only establishes
    // an identity when they did not, and does so before REST authentication/hardening callbacks.
    add_filter('determine_current_user', __NAMESPACE__ . '\\resolve_bearer_identity', priority: 30);
    add_filter('rest_authentication_errors', __NAMESPACE__ . '\\reject_invalid_bearer', priority: 5);

    // This hook runs only after WP_REST_Server matches a registered route and before its permission
    // callback, so both OAuth authorization and missing-credential challenges use authoritative routing.
    add_filter(
        'rest_request_before_callbacks',
        __NAMESPACE__ . '\\authorize_routed_request',
        priority: 5,
        accepted_args: 3,
    );
}

/**
 * Establish a WordPress identity without making any route authorization decision.
 *
 * @param mixed $user Existing identity established by WordPress.
 * @return mixed The existing identity, or the OAuth subject ID after successful validation.
 */
function resolve_bearer_identity(mixed $user): mixed
{
    $auth = get_authorization_header();

    return resolve_bearer_identity_using(
        $user,
        $auth,
        static fn(string $authorization): array => validate_bearer_credential($authorization),
    );
}

/**
 * Testable identity-resolution core. The production entry point always supplies the cryptographic
 * League OAuth resource-server validator above; route or query values are deliberately unavailable.
 *
 * @param \Closure(string): array{user_id: int, scopes: list<string>} $validator
 * @return mixed
 */
function resolve_bearer_identity_using(mixed $user, string $auth, \Closure $validator): mixed
{
    reset_request_context();

    if (has_existing_identity($user)) {
        return $user;
    }
    if (!has_bearer_scheme($auth)) {
        return $user;
    }
    if (!has_bearer_authorization($auth)) {
        record_authentication_error('Malformed OAuth Bearer credential.');
        return $user;
    }

    try {
        $identity = $validator(normalize_bearer_authorization($auth));
        $user_id = $identity['user_id'];
        if ($user_id <= 0) {
            record_authentication_error('Invalid OAuth token subject.');
            return $user;
        }

        wp_set_current_user($user_id);
        record_oauth_identity($user_id, $identity['scopes']);

        return $user_id;
    } catch (OAuthServerException) {
        record_authentication_error('Invalid, expired, or revoked OAuth access token.');
        return $user;
    } catch (\Throwable) {
        record_authentication_error('OAuth authentication failed.', status: 500);
        return $user;
    }
}

/**
 * Validate signature, validity window, revocation, audience, subject, and granted scopes.
 *
 * The optional server exists for focused tests; production always builds the server from Novamira's
 * own key and access-token repository.
 *
 * @return array{user_id: int, scopes: list<string>}
 * @throws OAuthServerException
 */
function validate_bearer_credential(string $auth, ?ResourceServer $server = null): array
{
    $server ??= ServerFactory\build_resource_server();
    $validated = $server->validateAuthenticatedRequest(Bridge\psr7_from_globals()->withHeader(
        'Authorization',
        normalize_bearer_authorization($auth),
    ));

    // RFC 8707: a token minted for another resource must never establish a WordPress identity.
    if ($validated->getAttribute('oauth_client_id') !== \Novamira\OAuth\resource_identifier()) {
        throw OAuthServerException::accessDenied('Token audience does not match this resource.');
    }

    $user_id = (int) $validated->getAttribute('oauth_user_id');
    if ($user_id <= 0) {
        throw OAuthServerException::accessDenied('Invalid token subject.');
    }

    return [
        'user_id' => $user_id,
        'scopes' => normalize_scopes($validated->getAttribute('oauth_scopes')),
    ];
}

/**
 * Return a stored validation error before later REST hardening callbacks run.
 */
function reject_invalid_bearer(mixed $result): mixed
{
    $error = request_authentication_error();
    if ($error === null) {
        return $result;
    }

    // A different authenticator must not turn a presented invalid Bearer credential into success.
    send_www_authenticate('invalid_token');
    return $error;
}

/**
 * Enforce OAuth's route boundary from the authoritative matched request route and method.
 */
function authorize_routed_request(mixed $result, mixed $handler, WP_REST_Request $request): mixed
{
    $route = $request->get_route();
    $method = strtoupper($request->get_method());
    $identity = request_oauth_identity();

    if ($identity === null) {
        return challenge_unauthenticated($result, $handler, $request);
    }

    if (!oauth_identity_may_use_route($route, $method)) {
        send_www_authenticate('insufficient_scope');
        return new WP_Error(
            'rest_oauth_route_forbidden',
            'This OAuth credential is not accepted on the requested REST route.',
            ['status' => 403],
        );
    }

    if (!scopes_authorize_routed_request($identity['scopes'], $route, $method)) {
        $required_scope = route_required_scope($route, $method);
        send_www_authenticate('insufficient_scope', $required_scope ?? 'abilities');
        return new WP_Error('rest_oauth_error', 'Token does not grant access to this REST route.', ['status' => 403]);
    }

    if (!current_user_can_access_mcp()) {
        send_www_authenticate('insufficient_scope', route_required_scope($route, $method) ?? 'abilities');
        return new WP_Error('rest_oauth_error', 'User is no longer allowed to manage Novamira.', [
            'status' => 403,
        ]);
    }

    // Preserve an earlier pre-dispatch response only after proving that OAuth may be used here.
    return $result;
}

function challenge_unauthenticated(mixed $result, mixed $handler, WP_REST_Request $request): mixed
{
    if ($result !== null || get_current_user_id() > 0 || has_bearer_scheme(get_authorization_header())) {
        return $result;
    }

    $required_scope = route_required_scope($request->get_route(), strtoupper($request->get_method()));
    if ($required_scope === null) {
        return $result;
    }

    $response = new WP_REST_Response([
        'code' => 'rest_oauth_required',
        'message' => 'OAuth authentication required.',
    ], 401);
    $response->header('WWW-Authenticate', www_authenticate_header(scope: $required_scope));
    return $response;
}

/**
 * RFC 6750 WWW-Authenticate challenge value.
 */
function www_authenticate_header(?string $error = null, string $scope = 'mcp'): string
{
    $value = 'Bearer resource_metadata="' . \Novamira\OAuth\Endpoints\Discovery\protected_resource_metadata_url() . '"';
    if ($error !== null) {
        $value .= ', error="' . $error . '"';
    }
    return $value . ', scope="' . $scope . '"';
}

function send_www_authenticate(string $error, string $scope = 'mcp'): void
{
    if (!headers_sent()) {
        header('WWW-Authenticate: ' . www_authenticate_header($error, $scope));
    }
}

/**
 * Existing OAuth protocol endpoint retained for backward compatibility.
 */
function is_mcp_route(string $route): bool
{
    return $route === '/mcp/novamira-oauth' || str_starts_with($route, '/mcp/novamira-oauth/');
}

/**
 * Exact REST routes on which a Novamira-established identity may survive post-routing checks.
 */
function oauth_identity_may_use_route(string $route, string $method): bool
{
    $method = strtoupper($method);
    if (is_mcp_route($route)) {
        return true;
    }
    if ($route === '/wp-abilities/v1/abilities') {
        return $method === 'GET' || $method === 'HEAD';
    }
    if ($method === 'GET' && preg_match('#^/wp-abilities/v1/abilities/[^/]+(?:/[^/]+)+$#', $route) === 1) {
        return true;
    }

    return $method === 'POST' && preg_match('#^/novamira/v1/abilities/[^/]+(?:/[^/]+)+/run$#', $route) === 1;
}

/** @param list<string> $scopes */
function scopes_authorize_routed_request(array $scopes, string $route, string $method): bool
{
    if (is_mcp_route($route)) {
        return in_array('mcp', $scopes, strict: true);
    }
    if (in_array('abilities', $scopes, strict: true)) {
        return true;
    }
    if (!in_array('abilities:read', $scopes, strict: true)) {
        return false;
    }

    return strtoupper($method) !== 'POST' || run_route_ability_is_readonly($route);
}

function route_required_scope(string $route, string $method): ?string
{
    if (!oauth_identity_may_use_route($route, $method)) {
        return null;
    }
    if (is_mcp_route($route)) {
        return 'mcp';
    }
    if (strtoupper($method) !== 'POST') {
        return 'abilities:read';
    }

    return run_route_ability_is_readonly($route) ? 'abilities:read' : 'abilities';
}

function run_route_ability_is_readonly(string $route): bool
{
    $name = run_route_ability_name($route);
    if ($name === null || !function_exists('wp_get_ability')) {
        return false;
    }

    $ability = wp_get_ability($name);
    if (!$ability instanceof \WP_Ability || $ability->get_meta_item('show_in_rest', false) !== true) {
        return false;
    }
    // @mago-expect analysis:mixed-assignment
    $annotations = $ability->get_meta_item('annotations', []);

    return is_array($annotations) && ($annotations['readonly'] ?? null) === true;
}

function run_route_ability_name(string $route): ?string
{
    $prefix = '/novamira/v1/abilities/';
    $suffix = '/run';
    if (!str_starts_with($route, $prefix) || !str_ends_with($route, $suffix)) {
        return null;
    }

    $encoded = substr($route, strlen($prefix), -strlen($suffix));
    $segments = array_values(array_filter(explode('/', $encoded), static fn(string $part): bool => $part !== ''));
    if (count($segments) < 2) {
        return null;
    }

    return implode('/', array_map('rawurldecode', $segments));
}

function get_authorization_header(): string
{
    $auth = trim($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if ($auth !== '') {
        return $auth;
    }

    return trim($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
}

function has_bearer_scheme(string $auth): bool
{
    return preg_match('/^\s*Bearer(?:\s|$)/i', $auth) === 1;
}

function has_bearer_authorization(string $auth): bool
{
    return preg_match('/^\s*Bearer\s+\S/i', $auth) === 1;
}

function normalize_bearer_authorization(string $auth): string
{
    $matches = [];
    if (preg_match('/^\s*Bearer\s+(.+?)\s*$/i', $auth, $matches) !== 1) {
        return $auth;
    }
    return 'Bearer ' . $matches[1];
}

/** @return list<string> */
function normalize_scopes(mixed $scopes): array
{
    if (is_string($scopes)) {
        $parts = preg_split('/\s+/', trim($scopes));
        $scopes = $parts === false ? [] : $parts;
    }
    if (!is_array($scopes)) {
        return [];
    }

    $normalized = [];
    // @mago-expect analysis:mixed-assignment
    foreach ($scopes as $scope) {
        if (!is_string($scope) || $scope === '') {
            continue;
        }
        $normalized[] = $scope;
    }
    return $normalized;
}

function current_user_can_access_mcp(): bool
{
    return \novamira_current_user_can_manage();
}

function has_existing_identity(mixed $user): bool
{
    return $user !== null && $user !== false && $user !== 0 && $user !== '0';
}

/**
 * Request-local proof and error storage. PHP normally serves one request per process; reset at the
 * start of determine_current_user also keeps persistent test/worker environments isolated.
 *
 * @return array{identity: array{user_id: int, scopes: list<string>}|null, error: WP_Error|null}
 */
function &request_context(): array
{
    static $context = ['identity' => null, 'error' => null];
    return $context;
}

function reset_request_context(): void
{
    $context = &request_context();
    $context = ['identity' => null, 'error' => null];
}

/** @param list<string> $scopes */
function record_oauth_identity(int $user_id, array $scopes): void
{
    $context = &request_context();
    $context['identity'] = ['user_id' => $user_id, 'scopes' => $scopes];
    $context['error'] = null;
}

function record_authentication_error(string $message, int $status = 401): void
{
    $context = &request_context();
    $context['identity'] = null;
    $context['error'] = new WP_Error('rest_oauth_error', $message, ['status' => $status]);
}

/** @return array{user_id: int, scopes: list<string>}|null */
function request_oauth_identity(): ?array
{
    $context = &request_context();
    return $context['identity'];
}

function request_authentication_error(): ?WP_Error
{
    $context = &request_context();
    return $context['error'];
}
