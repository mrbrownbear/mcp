<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace Novamira\Troubleshoot\Admin;

if (!defined('ABSPATH')) {
    exit();
}

const PAGE_SLUG = 'novamira-troubleshoot';

/**
 * Register the standalone Troubleshoot page. The diagnostics are not a step in the connection
 * flow, so they live in their own submenu rather than inside the Connect page; the Connect page
 * links here when something is not working.
 */
function register_menu(): void
{
    add_submenu_page(
        parent_slug: 'novamira-connect',
        page_title: __('Troubleshoot', domain: 'novamira'),
        menu_title: __('Troubleshoot', domain: 'novamira'),
        capability: \novamira_manage_capability(),
        menu_slug: PAGE_SLUG,
        callback: __NAMESPACE__ . '\\render_page',
    );
}

/**
 * Best guess at which connection method to diagnose, since this page is reached outside the
 * Connect flow where the method was known. The strongest signal is the last authenticated MCP
 * request, which is recorded per method; failing that, the presence of MCP Application Passwords
 * or registered OAuth clients. Empty string means "unknown", and the panel then checks both.
 *
 * @return 'oauth'|'password'|''
 */
function detect_connection_method(): string
{
    // @mago-expect analysis:mixed-assignment
    $last = get_option('novamira_mcp_last_request', default_value: []);
    if (is_array($last)) {
        $oauth = is_int($last['oauth'] ?? null) ? $last['oauth'] : 0;
        $password = is_int($last['password'] ?? null) ? $last['password'] : 0;
        if ($oauth > 0 || $password > 0) {
            return $oauth >= $password ? 'oauth' : 'password';
        }
    }

    if (function_exists('novamira_get_mcp_passwords') && \novamira_get_mcp_passwords() !== []) {
        return 'password';
    }

    if (
        function_exists('Novamira\\OAuth\\ClientValidation\\active_client_count')
        && \Novamira\OAuth\ClientValidation\active_client_count() > 0
    ) {
        return 'oauth';
    }

    return '';
}

function render_page(): void
{
    if (!\novamira_current_user_can_manage()) {
        return;
    }
    $method = detect_connection_method();
    if (function_exists('novamira_render_admin_header')) {
        \novamira_render_admin_header();
    }
    ?>
    <div class="wrap">
        <h1 class="wp-heading-inline"><?php esc_html_e('Troubleshoot the Connection', domain: 'novamira'); ?></h1>
        <hr class="wp-header-end">
        <p class="description" style="max-width:40em;"><?php esc_html_e(
            'Run these checks when an AI client cannot connect. They probe this site the way a client does and point at what to fix.',
            domain: 'novamira',
        ); ?></p>
        <?php \Novamira\Troubleshoot\UI\render_panel(
            context: 'troubleshoot',
            method: $method,
            with_method_picker: true,
        ); ?>
    </div>
    <?php
}
