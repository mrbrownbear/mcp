<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace Novamira\OAuth\Schema;

if (!defined('ABSPATH')) {
    exit();
}

const SCHEMA_VERSION_OPTION = 'novamira_oauth_schema_version';

const CURRENT_SCHEMA_VERSION = '2';

function maybe_install(): void
{
    if (get_option(SCHEMA_VERSION_OPTION) === CURRENT_SCHEMA_VERSION) {
        return;
    }
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    // @mago-expect lint:no-global
    global $wpdb;
    /** @var \wpdb $wpdb */
    $c = $wpdb->get_charset_collate();
    $p = $wpdb->prefix . 'novamira_oauth_';

    dbDelta("CREATE TABLE {$p}clients (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        client_id VARCHAR(64) NOT NULL,
        client_name VARCHAR(191) NOT NULL,
        redirect_uris TEXT NOT NULL,
        is_confidential TINYINT(1) NOT NULL DEFAULT 0,
        client_secret_hash VARCHAR(255) DEFAULT NULL,
        created_at DATETIME NOT NULL,
        last_used_at DATETIME DEFAULT NULL,
        registered_by_ip_hash CHAR(64) NOT NULL,
        admin_created TINYINT(1) NOT NULL DEFAULT 0,
        PRIMARY KEY (id),
        UNIQUE KEY client_id (client_id)
    ) {$c};");

    dbDelta("CREATE TABLE {$p}auth_codes (
        identifier_hash CHAR(64) NOT NULL,
        client_id VARCHAR(64) NOT NULL,
        user_id BIGINT UNSIGNED NOT NULL,
        expires_at DATETIME NOT NULL,
        scopes TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        revoked TINYINT(1) NOT NULL DEFAULT 0,
        PRIMARY KEY (identifier_hash),
        KEY expires_at (expires_at)
    ) {$c};");

    dbDelta("CREATE TABLE {$p}access_tokens (
        identifier_hash CHAR(64) NOT NULL,
        client_id VARCHAR(64) NOT NULL,
        user_id BIGINT UNSIGNED NOT NULL,
        expires_at DATETIME NOT NULL,
        scopes TEXT NOT NULL,
        revoked TINYINT(1) NOT NULL DEFAULT 0,
        PRIMARY KEY (identifier_hash),
        KEY expires_at (expires_at),
        KEY user_id (user_id)
    ) {$c};");

    dbDelta("CREATE TABLE {$p}refresh_tokens (
        identifier_hash CHAR(64) NOT NULL,
        access_token_hash CHAR(64) NOT NULL,
        expires_at DATETIME NOT NULL,
        revoked TINYINT(1) NOT NULL DEFAULT 0,
        PRIMARY KEY (identifier_hash),
        KEY expires_at (expires_at)
    ) {$c};");

    update_option(SCHEMA_VERSION_OPTION, CURRENT_SCHEMA_VERSION, autoload: false);
}

function gc(): void
{
    // @mago-expect lint:no-global
    global $wpdb;
    /** @var \wpdb $wpdb */
    $cutoff = gmdate('Y-m-d H:i:s', time() - (30 * DAY_IN_SECONDS));
    $p = $wpdb->prefix . 'novamira_oauth_';
    foreach (['auth_codes', 'access_tokens', 'refresh_tokens'] as $t) {
        $table = $p . $t;
        // @mago-expect analysis:possibly-invalid-argument
        $sql = $wpdb->prepare("DELETE FROM `{$table}` WHERE expires_at < %s", $cutoff);
        // @mago-expect analysis:possibly-invalid-argument
        $wpdb->query($sql);
    }
}

if (!wp_next_scheduled('novamira_oauth_gc')) {
    wp_schedule_event(timestamp: time() + HOUR_IN_SECONDS, recurrence: 'daily', hook: 'novamira_oauth_gc');
}
add_action('novamira_oauth_gc', __NAMESPACE__ . '\\gc');
