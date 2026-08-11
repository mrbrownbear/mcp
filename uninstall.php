<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit();
}

const NOVAMIRA_UNINSTALL_PLAN_OPTION = 'novamira_uninstall_plan';

/**
 * @return array{delete_oauth: bool, delete_application_passwords: bool}
 */
function novamira_uninstall_plan(): array
{
    /** @var mixed $stored */
    $stored = get_site_option(NOVAMIRA_UNINSTALL_PLAN_OPTION, default_value: []);
    if (!is_array($stored)) {
        $stored = [];
    }

    return [
        // Preserve the uninstall behavior used before cleanup choices were introduced.
        'delete_oauth' => !array_key_exists('delete_oauth', $stored) || $stored['delete_oauth'] === true,
        'delete_application_passwords' => ($stored['delete_application_passwords'] ?? false) === true,
    ];
}

function novamira_uninstall_current_site(bool $delete_oauth): void
{
    $wpdb = novamira_uninstall_wpdb();

    $chat_table = $wpdb->prefix . 'novamira_chat_sessions';
    $wpdb->query("DROP TABLE IF EXISTS {$chat_table}");

    delete_option('novamira_chat_schema_version');
    delete_option('novamira_chat_sessions');

    if ($delete_oauth) {
        foreach (novamira_uninstall_oauth_tables() as $table) {
            $wpdb->query("DROP TABLE IF EXISTS {$table}");
        }

        delete_option('novamira_oauth_schema_version');
        delete_option('novamira_oauth_private_key');
        delete_option('novamira_oauth_public_key');
        delete_option('novamira_oauth_encryption_key');
    }

    wp_clear_scheduled_hook('novamira_oauth_gc');
}

/**
 * @return list<string>
 */
function novamira_uninstall_oauth_tables(): array
{
    $wpdb = novamira_uninstall_wpdb();

    return [
        $wpdb->prefix . 'novamira_oauth_clients',
        $wpdb->prefix . 'novamira_oauth_auth_codes',
        $wpdb->prefix . 'novamira_oauth_access_tokens',
        $wpdb->prefix . 'novamira_oauth_device_codes',
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

function novamira_uninstall_application_passwords(): void
{
    $wpdb = novamira_uninstall_wpdb();
    // @mago-expect analysis:possibly-invalid-argument -- $wpdb->usermeta is WordPress' users table.
    $query = $wpdb->prepare(
        "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s",
        WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS,
    );
    if (!is_string($query)) {
        return;
    }
    $user_ids = $wpdb->get_col($query);

    foreach (array_unique(array_map('intval', $user_ids)) as $user_id) {
        $passwords = WP_Application_Passwords::get_user_application_passwords($user_id);
        foreach ($passwords as $password) {
            if (!novamira_uninstall_is_application_password($password)) {
                continue;
            }

            $uuid = is_string($password['uuid'] ?? null) ? $password['uuid'] : '';
            if ($uuid !== '') {
                WP_Application_Passwords::delete_application_password($user_id, $uuid);
            }
        }
    }
}

/** @param array<string, mixed> $password */
function novamira_uninstall_is_application_password(array $password): bool
{
    $name = is_string($password['name'] ?? null) ? $password['name'] : '';
    return str_starts_with($name, 'Novamira');
}

$novamira_uninstall_plan = novamira_uninstall_plan();

if ($novamira_uninstall_plan['delete_application_passwords']) {
    novamira_uninstall_application_passwords();
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
        novamira_uninstall_current_site($novamira_uninstall_plan['delete_oauth']);
        restore_current_blog();
    }
    delete_site_option(NOVAMIRA_UNINSTALL_PLAN_OPTION);
    return;
}

novamira_uninstall_current_site($novamira_uninstall_plan['delete_oauth']);
delete_site_option(NOVAMIRA_UNINSTALL_PLAN_OPTION);
