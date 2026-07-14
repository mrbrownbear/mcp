<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace Novamira\OAuth\Endpoints\Register;

use Novamira\OAuth\ClientValidation;
use Novamira\OAuth\Repositories\ClientRepository;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

if (!defined('ABSPATH')) {
    exit();
}

function register(): void
{
    register_rest_route('novamira/v1', route: '/oauth/register', args: [
        'methods' => 'POST',
        'permission_callback' => '__return_true',
        'callback' => __NAMESPACE__ . '\\handle',
    ]);
}

// @mago-expect lint:cyclomatic-complexity
function handle(WP_REST_Request $req): WP_REST_Response|WP_Error
{
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '';
    ClientValidation\prune_stale_unused_clients();
    if ($client_ip !== '' && !ClientValidation\check_and_increment_rate_limit($client_ip)) {
        return new WP_Error('rate_limited', 'Too many registrations', ['status' => 429]);
    }
    if ($client_ip !== '' && ClientValidation\client_count_for_ip($client_ip) >= ClientValidation\MAX_CLIENTS_PER_IP) {
        return new WP_Error('rate_limited', 'Too many registered clients from this address', ['status' => 429]);
    }
    if (ClientValidation\client_count() >= ClientValidation\MAX_CLIENTS_PER_SITE) {
        return new WP_Error('cap_reached', 'Client cap reached', ['status' => 503]);
    }

    $body = $req->get_json_params();
    // @mago-expect analysis:mixed-assignment
    $client_name = sanitize_text_field(trim((string) ($body['client_name'] ?? '')));
    if ($client_name === '' || strlen($client_name) > 191) {
        return new WP_Error('invalid_request', 'client_name must be 1..191 chars', ['status' => 400]);
    }

    // @mago-expect analysis:mixed-assignment
    $redirect_uris = $body['redirect_uris'] ?? null;
    if (!is_array($redirect_uris) || $redirect_uris === []) {
        return new WP_Error('invalid_request', 'redirect_uris must be a non-empty array', ['status' => 400]);
    }
    if (count($redirect_uris) > 5) {
        return new WP_Error('invalid_request', 'Max 5 redirect_uris', ['status' => 400]);
    }

    // @mago-expect analysis:mixed-operand
    $dev_mode = defined('WP_DEBUG') && (bool) \WP_DEBUG;
    $clean_uris = [];
    foreach ($redirect_uris as $uri) {
        $uri = is_string($uri) ? trim($uri) : '';
        if (
            $uri === ''
            || strlen($uri) > ClientValidation\MAX_REDIRECT_URI_LENGTH
            || !ClientValidation\is_allowed_redirect_uri($uri, $dev_mode)
        ) {
            return new WP_Error('invalid_redirect_uri', sprintf('redirect_uri not allowed: %s', esc_html($uri)), [
                'status' => 400,
            ]);
        }
        $clean_uris[] = $uri;
    }

    $clean_uris = array_values(array_unique($clean_uris));
    $client_id = (new ClientRepository())->create($client_name, $clean_uris, $client_ip);

    return new WP_REST_Response([
        'client_id' => $client_id,
        'client_name' => $client_name,
        'redirect_uris' => $clean_uris,
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code', 'refresh_token'],
        'response_types' => ['code'],
    ], 201);
}
