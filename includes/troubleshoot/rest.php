<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace Novamira\Troubleshoot\Rest;

use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

if (!defined('ABSPATH')) {
    exit();
}

function register_routes(): void
{
    $permission = static fn(): bool => is_user_logged_in() && \novamira_current_user_can_manage();

    register_rest_route('novamira/v1', route: '/troubleshoot/run-checks', args: [
        'methods' => 'POST',
        'permission_callback' => $permission,
        'callback' => __NAMESPACE__ . '\\run_checks',
    ]);

    register_rest_route('novamira/v1', route: '/troubleshoot/client-id', args: [
        'methods' => 'POST',
        'permission_callback' => $permission,
        'callback' => __NAMESPACE__ . '\\client_id',
    ]);
}

function run_checks(WP_REST_Request $req): WP_REST_Response
{
    // @mago-expect analysis:mixed-assignment
    $raw = $req->get_json_params()['method'] ?? null;
    $method = in_array($raw, ['oauth', 'password'], strict: true) ? $raw : null;

    $checks = \Novamira\Troubleshoot\Checks\run_all($method);
    // run_all() already probed for security/edge layers; current_security_edge_layers() caches that
    // result for this request, so the report reuses it without a second self-request.
    $layers = \Novamira\Troubleshoot\Checks\current_security_edge_layers();
    $meta = [
        'site_url' => home_url('/'),
        'novamira_version' => defined('NOVAMIRA_VERSION') ? NOVAMIRA_VERSION : '',
        'wp_version' => get_bloginfo('version'),
        'php_version' => PHP_VERSION,
        'method' => $method ?? '',
    ];

    return new WP_REST_Response([
        'checks' => $checks,
        'layers' => $layers,
        'report' => \Novamira\Troubleshoot\Checks\build_support_report($meta, $layers, $checks),
    ]);
}

function client_id(WP_REST_Request $req): WP_REST_Response|WP_Error
{
    // @mago-expect analysis:mixed-assignment
    $raw = $req->get_json_params()['client'] ?? null;
    $result = \Novamira\Troubleshoot\ClientIds\generate(is_string($raw) ? $raw : '');
    if (is_wp_error($result)) {
        return $result;
    }
    return new WP_REST_Response($result, 201);
}
