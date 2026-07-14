<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit();
}

function novamira_uninstall_current_site(): void
{
    $wpdb = novamira_uninstall_wpdb();

    foreach (novamira_uninstall_tables() as $table) {
        $wpdb->query("DROP TABLE IF EXISTS {$table}");
    }

    delete_option('novamira_chat_schema_version');
    delete_option('novamira_chat_sessions');
    delete_option('novamira_oauth_schema_version');
    delete_option('novamira_oauth_private_key');
    delete_option('novamira_oauth_public_key');
    delete_option('novamira_oauth_encryption_key');

    wp_clear_scheduled_hook('novamira_oauth_gc');
}

/**
 * @return list<string>
 */
function novamira_uninstall_tables(): array
{
    $wpdb = novamira_uninstall_wpdb();

    return [
        $wpdb->prefix . 'novamira_chat_sessions',
        $wpdb->prefix . 'novamira_oauth_clients',
        $wpdb->prefix . 'novamira_oauth_auth_codes',
        $wpdb->prefix . 'novamira_oauth_access_tokens',
        $wpdb->prefix . 'novamira_oauth_refresh_tokens',
    ];
}

function novamira_uninstall_wpdb(): wpdb
{
    // @mago-expect lint:no-global -- $wpdb is WordPress' database handle.
    global $wpdb;

    /** @var wpdb $wpdb */
    return $wpdb;
}

if (is_multisite()) {
    // @mago-expect analysis:mixed-assignment -- WordPress returns site ids when fields=ids.
    $site_ids = get_sites(['fields' => 'ids', 'number' => 0]);
    if (!is_array($site_ids)) {
        return;
    }

    // @mago-expect analysis:mixed-assignment
    foreach ($site_ids as $site_id) {
        switch_to_blog((int) $site_id);
        novamira_uninstall_current_site();
        restore_current_blog();
    }
    return;
}

novamira_uninstall_current_site();
