<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

if ($argc !== 3) {
    exit(2);
}

define('ABSPATH', __DIR__ . '/');
define('NOVAMIRA_SANDBOX_DIR', rtrim($argv[1], '/') . '/');

if ($argv[2] === 'activation') {
    define('WP_SANDBOX_SCRAPING', true);
}

function add_action(): bool
{
    return true;
}

function wp_json_encode(mixed $value): string|false
{
    return json_encode($value);
}

require dirname(__DIR__, 2) . '/includes/sandbox-loader.php';

echo 'runner-complete';
