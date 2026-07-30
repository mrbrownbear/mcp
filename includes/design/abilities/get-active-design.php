<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace Novamira\Design\Abilities\GetActive;

use Novamira\Design\Abilities;
use Novamira\Design\Contract;
use Novamira\Design\Library;
use Novamira\Design\Store;

if (!defined('ABSPATH')) {
    exit();
}

function register(): void
{
    if (!function_exists('wp_register_ability')) {
        return;
    }

    wp_register_ability('novamira/get-active-design', [
        'label' => __('Get Active Design', domain: 'novamira'),
        'description' => __(
            'Return the active site design system as raw DESIGN.md plus structured tokens, dials, guidance, provenance, and readiness. Read this before visual work and build within the returned contract.',
            domain: 'novamira',
        ),
        'category' => Abilities\CATEGORY,
        'input_schema' => [
            'type' => 'object',
            'default' => [],
            'properties' => new \stdClass(),
        ],
        'output_schema' => [
            'type' => 'object',
            'properties' => array_merge([
                'active' => ['type' => 'boolean'],
                'slug' => ['type' => 'string'],
                'name' => ['type' => 'string'],
                'description' => ['type' => 'string'],
                'content' => ['type' => 'string'],
            ], Contract\ability_output_properties()),
            'required' => ['active'],
        ],
        'execute_callback' => static function (array $input): array {
            $slug = Store\get_active_slug();
            if ($slug === '') {
                return ['active' => false];
            }
            $record = Library\find($slug);
            if ($record === null) {
                return ['active' => false];
            }
            return array_merge([
                'active' => true,
                'slug' => $record['slug'],
                'name' => $record['name'],
                'description' => $record['description'],
                'content' => $record['content'],
            ], Contract\inspect($record['content']));
        },
        'permission_callback' => 'novamira_permission_callback',
        'meta' => [
            'annotations' => [
                'readonly' => true,
                'destructive' => false,
                'idempotent' => true,
            ],
            'mcp' => ['public' => true, 'type' => 'tool'],
        ],
    ]);
}
