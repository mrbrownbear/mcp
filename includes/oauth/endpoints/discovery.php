<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace Novamira\OAuth\Endpoints\Discovery;

if (!defined('ABSPATH')) {
    exit();
}

function register(): void
{
    add_action('init', __NAMESPACE__ . '\\maybe_serve', priority: 1);
}

function maybe_serve(): void
{
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
    if ($path === '/.well-known/oauth-protected-resource') {
        header('Content-Type: application/json; charset=UTF-8');
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        echo
            wp_json_encode([
                'resource' => \Novamira\OAuth\resource_identifier(),
                'authorization_servers' => [home_url()],
                'bearer_methods_supported' => ['header'],
                'scopes_supported' => ['mcp'],
            ])
        ;
        exit();
    }
    if ($path !== '/.well-known/oauth-authorization-server') {
        return;
    }
    $base = rest_url('novamira/v1/oauth');
    header('Content-Type: application/json; charset=UTF-8');
    // The authorization endpoint runs in the wp-admin cookie context (see
    // endpoints/authorize.php) rather than under /wp-json, so it keeps working on sites
    // where REST cookie authentication is disabled. The remaining endpoints stay on REST.
    // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    echo
        wp_json_encode([
            'issuer' => home_url(),
            'authorization_endpoint' => admin_url('admin.php?page=novamira-oauth-authorize'),
            'token_endpoint' => $base . '/token',
            'registration_endpoint' => $base . '/register',
            'revocation_endpoint' => $base . '/revoke',
            'introspection_endpoint' => $base . '/introspect',
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['none'],
            'scopes_supported' => ['mcp'],
        ])
    ;
    exit();
}
