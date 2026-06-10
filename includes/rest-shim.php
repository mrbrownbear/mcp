<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit();
}

add_action('rest_api_init', callback: 'novamira_register_ability_run_rest_shim');

/**
 * Register a schema-agnostic POST runner for REST-visible WordPress abilities.
 */
function novamira_register_ability_run_rest_shim(): void
{
    register_rest_route(
        route_namespace: 'novamira/v1',
        route: '/abilities/(?P<namespace>[^/]+)/(?P<ability>[^/]+)/run',
        args: [
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => 'novamira_rest_run_ability',
            'permission_callback' => 'novamira_rest_run_ability_permission',
            'args' => [
                'namespace' => [
                    'type' => 'string',
                    'required' => true,
                ],
                'ability' => [
                    'type' => 'string',
                    'required' => true,
                ],
            ],
        ],
    );
}

/**
 * Enforce Novamira's enabled state and manage permission at the REST route boundary.
 */
function novamira_rest_run_ability_permission(): bool|WP_Error
{
    if (!novamira_is_enabled()) {
        return new WP_Error('novamira_disabled', __('Novamira AI Abilities are disabled.', domain: 'novamira'), [
            'status' => 403,
        ]);
    }

    if (!novamira_current_user_can_manage()) {
        return new WP_Error(
            'novamira_forbidden',
            __('You are not allowed to manage Novamira settings.', domain: 'novamira'),
            ['status' => 403],
        );
    }

    return true;
}

/**
 * Execute a REST-visible ability with body JSON shaped as `{ "input": <any JSON> }`.
 */
function novamira_rest_run_ability(WP_REST_Request $request): mixed
{
    if (!function_exists('wp_get_ability')) {
        return new WP_Error(
            'novamira_abilities_api_unavailable',
            __('The WordPress Abilities API is unavailable.', domain: 'novamira'),
            ['status' => 500],
        );
    }

    $ability_name = (string) $request['namespace'] . '/' . (string) $request['ability'];
    $ability = wp_get_ability($ability_name);
    if (!$ability instanceof WP_Ability) {
        return new WP_Error(
            'novamira_ability_not_found',
            sprintf(__('Ability not found: %s', domain: 'novamira'), $ability_name),
            ['status' => 404],
        );
    }

    if ($ability->get_meta_item('show_in_rest', false) !== true) {
        return new WP_Error(
            'novamira_ability_hidden',
            sprintf(__('Ability is not exposed through REST: %s', domain: 'novamira'), $ability_name),
            ['status' => 404],
        );
    }

    $body = $request->get_json_params();
    /** @var mixed $input */
    $input = array_key_exists('input', $body) ? $body['input'] : null;

    return $ability->execute($input);
}
