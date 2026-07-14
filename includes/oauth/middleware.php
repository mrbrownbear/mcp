<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace Novamira\OAuth\Middleware;

use League\OAuth2\Server\Exception\OAuthServerException;
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
    add_filter('rest_authentication_errors', __NAMESPACE__ . '\\authenticate', priority: 20);
    add_filter('rest_pre_dispatch', __NAMESPACE__ . '\\challenge_unauthenticated', priority: 10, accepted_args: 3);
}

function challenge_unauthenticated(mixed $result, mixed $server, WP_REST_Request $request): mixed
{
    if ($result !== null) {
        return $result;
    }
    $route = $request->get_route();
    if (!is_mcp_route($route)) {
        return null;
    }
    if (has_bearer_authorization(get_authorization_header())) {
        return null;
    }
    $response = new WP_REST_Response([
        'code' => 'rest_oauth_required',
        'message' => 'OAuth authentication required.',
    ], 401);
    $response->header('WWW-Authenticate', www_authenticate_header());
    return $response;
}

/**
 * RFC 6750 WWW-Authenticate challenge value. Always points clients at the protected-resource
 * metadata and declares the required scope; an $error (invalid_token / insufficient_scope) is
 * added when a presented token is rejected, so a client can tell "no token" from "bad token".
 */
function www_authenticate_header(?string $error = null): string
{
    $value = 'Bearer resource_metadata="' . home_url('/.well-known/oauth-protected-resource') . '"';
    if ($error !== null) {
        $value .= ', error="' . $error . '"';
    }
    return $value . ', scope="mcp"';
}

/**
 * Emit the WWW-Authenticate header for a rejected Bearer token. authenticate() runs on
 * rest_authentication_errors, before REST output, so the header still reaches the client.
 */
function send_www_authenticate(string $error): void
{
    if (!headers_sent()) {
        header('WWW-Authenticate: ' . www_authenticate_header($error));
    }
}

function authenticate(mixed $result): mixed
{
    if ($result !== null) {
        return $result;
    }

    $auth = get_authorization_header();
    if (!has_bearer_authorization($auth)) {
        return null;
    }
    if (!request_targets_mcp_route()) {
        return null;
    }

    try {
        $server = ServerFactory\build_resource_server();
        $validated = $server->validateAuthenticatedRequest(Bridge\psr7_from_globals()->withHeader(
            'Authorization',
            normalize_bearer_authorization($auth),
        ));
        // RFC 8707 / MCP: the token's audience (league exposes the aud claim as oauth_client_id)
        // must name this resource, so a token issued for a different resource is not accepted here.
        if ($validated->getAttribute('oauth_client_id') !== \Novamira\OAuth\resource_identifier()) {
            send_www_authenticate('invalid_token');
            return new WP_Error('rest_oauth_error', 'Token audience does not match this resource.', [
                'status' => 401,
            ]);
        }
        if (!has_mcp_scope($validated->getAttribute('oauth_scopes'))) {
            send_www_authenticate('insufficient_scope');
            return new WP_Error('rest_oauth_error', 'Token is missing the required mcp scope.', ['status' => 403]);
        }
        $user_id = (int) $validated->getAttribute('oauth_user_id');
        if ($user_id <= 0) {
            send_www_authenticate('invalid_token');
            return new WP_Error('rest_oauth_error', 'Invalid token subject.', ['status' => 401]);
        }
        wp_set_current_user($user_id);
        if (!current_user_can_access_mcp()) {
            send_www_authenticate('insufficient_scope');
            return new WP_Error('rest_oauth_error', 'User is no longer allowed to use Novamira MCP.', [
                'status' => 403,
            ]);
        }
        return true;
    } catch (OAuthServerException $e) {
        send_www_authenticate('invalid_token');
        return new WP_Error('rest_oauth_error', $e->getMessage(), ['status' => $e->getHttpStatusCode()]);
    } catch (\Throwable $e) {
        return new WP_Error('rest_oauth_error', 'Authentication failed.', ['status' => 500]);
    }
}

/**
 * The OAuth flow is scoped to its own MCP server at `/mcp/novamira-oauth` (registered in
 * novamira.php). The canonical `/mcp/novamira` — used by Application Password installs — is
 * deliberately excluded so the OAuth challenge never fires on it. Note `/mcp/novamira-oauth`
 * does not start with `/mcp/novamira/` (dash, not slash), so matching must be exact on the
 * `-oauth` slug, never a loose `/mcp/novamira` prefix.
 */
function is_mcp_route(string $route): bool
{
    return $route === '/mcp/novamira-oauth' || str_starts_with($route, '/mcp/novamira-oauth/');
}

function get_authorization_header(): string
{
    $auth = trim($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if ($auth !== '') {
        return $auth;
    }

    return trim($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
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

function has_mcp_scope(mixed $scopes): bool
{
    if (is_string($scopes)) {
        $parts = preg_split('/\s+/', trim($scopes));
        $scopes = $parts === false ? [] : $parts;
    }
    if (!is_array($scopes)) {
        return false;
    }
    return in_array('mcp', $scopes, strict: true);
}

function current_user_can_access_mcp(): bool
{
    return \novamira_current_user_can_manage();
}

function request_targets_mcp_route(): bool
{
    $rest_route = $_GET['rest_route'] ?? null;
    if (is_string($rest_route) && is_mcp_route('/' . ltrim($rest_route, characters: '/'))) {
        return true;
    }

    $request_uri = $_SERVER['REQUEST_URI'] ?? '';
    if ($request_uri === '') {
        return false;
    }

    $path = parse_url($request_uri, PHP_URL_PATH);
    if (!is_string($path)) {
        return false;
    }
    $path = rawurldecode($path);

    if (function_exists('rest_url')) {
        $mcp_path = parse_url(rest_url('mcp/novamira-oauth'), PHP_URL_PATH);
        if (is_string($mcp_path) && path_matches_prefix($path, $mcp_path)) {
            return true;
        }
    }

    $rest_prefix = function_exists('rest_get_url_prefix') ? rest_get_url_prefix() : 'wp-json';
    $rest_prefix = trim($rest_prefix, characters: '/');
    if ($rest_prefix === '') {
        return false;
    }

    return preg_match('#/' . preg_quote($rest_prefix, delimiter: '#') . '/mcp/novamira-oauth(?:/|$)#', $path) === 1;
}

function path_matches_prefix(string $path, string $prefix): bool
{
    $prefix = rtrim($prefix, characters: '/');
    return $prefix !== '' && ($path === $prefix || str_starts_with($path, $prefix . '/'));
}
