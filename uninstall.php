<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit();
}

function novamira_uninstall_drop_chat_table_current_site(): void
{
    $wpdb = novamira_uninstall_wpdb();

    $table = $wpdb->prefix . 'novamira_chat_sessions';
    $wpdb->query("DROP TABLE IF EXISTS {$table}");
    delete_option('novamira_chat_schema_version');
    delete_option('novamira_chat_sessions');
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
        novamira_uninstall_drop_chat_table_current_site();
        restore_current_blog();
    }
    return;
}

novamira_uninstall_drop_chat_table_current_site();
