<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace Novamira\OAuth\CanonicalMcp;

use WP_Error;
use WP_REST_Request;

if (!defined('ABSPATH')) {
    exit();
}

/**
 * Make the public /mcp/novamira route the canonical OAuth resource while retaining
 * /mcp/novamira-oauth as a backwards-compatible alias handled by the original middleware.
 */
function register(): void
{
    remove_filter(
        'rest_request_before_callbacks',
        'Novamira\\OAuth\\Middleware\\authorize_routed_request',
        5,
    );
    add_filter(
        'rest_request_before_callbacks',
        __NAMESPACE__ . '\\authorize_routed_request',
        5,
        3,
    );

    remove_filter(
        'rest_request_after_callbacks',
        'Novamira\\OAuth\\Middleware\\attach_www_authenticate_challenge',
        5,
    );
    add_filter(
        'rest_request_after_callbacks',
        __NAMESPACE__ . '\\attach_www_authenticate_challenge',
        5,
        3,
    );
}

function is_canonical_mcp_route(string $route): bool
{
    return $route === '/mcp/novamira' || str_starts_with($route, '/mcp/novamira/');
}

function authorize_routed_request(mixed $result, mixed $handler, WP_REST_Request $request): mixed
{
    $route = $request->get_route();
    if (!is_canonical_mcp_route($route)) {
        return \Novamira\OAuth\Middleware\authorize_routed_request($result, $handler, $request);
    }

    $identity = \Novamira\OAuth\Middleware\request_oauth_identity();
    if ($identity === null) {
        if (
            $result !== null
            || get_current_user_id() > 0
            || \Novamira\OAuth\Middleware\has_bearer_scheme(
                \Novamira\OAuth\Middleware\get_authorization_header(),
            )
        ) {
            return $result;
        }

        return new WP_Error('rest_oauth_required', 'OAuth authentication required.', ['status' => 401]);
    }

    if (!\Novamira\OAuth\Middleware\scopes_authorize_routed_request(
        $identity['scopes'],
        $route,
        strtoupper($request->get_method()),
    )) {
        return new WP_Error('rest_oauth_error', 'Token does not grant access to this REST route.', [
            'status' => 403,
        ]);
    }

    if (!\Novamira\OAuth\Middleware\current_user_can_access_mcp()) {
        return new WP_Error('rest_oauth_error', 'User is no longer allowed to manage Novamira.', [
            'status' => 403,
        ]);
    }

    return $result;
}

function attach_www_authenticate_challenge(
    mixed $response,
    mixed $handler,
    WP_REST_Request $request,
): mixed {
    if (!is_canonical_mcp_route($request->get_route())) {
        return \Novamira\OAuth\Middleware\attach_www_authenticate_challenge($response, $handler, $request);
    }

    if (!$response instanceof WP_Error) {
        return $response;
    }

    $code = $response->get_error_code();
    $challenge = null;

    if ($code === 'rest_oauth_required') {
        $challenge = \Novamira\OAuth\Middleware\www_authenticate_header(scope: 'mcp');
    } elseif (
        $code === 'rest_oauth_error'
        && \Novamira\OAuth\Middleware\error_status($response) === 403
    ) {
        $challenge = \Novamira\OAuth\Middleware\www_authenticate_header('insufficient_scope', 'mcp');
    }

    if ($challenge === null) {
        return $response;
    }

    $converted = rest_convert_error_to_response($response);
    $converted->header('WWW-Authenticate', $challenge);

    return $converted;
}
