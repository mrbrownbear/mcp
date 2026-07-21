<?php
// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

if (!defined('ABSPATH')) {
    define('ABSPATH', '/');
}
if (!function_exists('add_action')) {
    function add_action(
        string $hook_name,
        callable|string $callback,
        int $priority = 10,
        int $accepted_args = 1,
    ): bool {
        $GLOBALS['novamira_test_actions'][] = [$hook_name, $callback, $priority, $accepted_args];
        return true;
    }
}
if (!function_exists('__')) {
    function __(string $text, string $domain = 'default'): string
    {
        return $text;
    }
}

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../includes/oauth/bootstrap.php';
require_once __DIR__ . '/../../includes/oauth/consent.php';
require_once __DIR__ . '/../../includes/oauth/endpoints/introspect.php';

final class AbilityScopeLifecycleTest extends TestCase
{
    #[DataProvider('authorizationScopeProvider')]
    public function testAuthorizationScopeValidationPreservesAbilityGrants(
        string $requested,
        ?string $expected,
    ): void {
        self::assertSame($expected, \Novamira\OAuth\normalize_authorization_scope($requested));
    }

    /** @return iterable<string, array{string, string|null}> */
    public static function authorizationScopeProvider(): iterable
    {
        yield 'default legacy' => ['', 'mcp'];
        yield 'readonly' => ['abilities:read', 'abilities:read'];
        yield 'full' => ['abilities', 'abilities'];
        yield 'full explicitly includes read without rewriting' => [
            'abilities abilities:read',
            'abilities abilities:read',
        ];
        yield 'mcp' => ['mcp', 'mcp'];
        yield 'legacy aliases' => ['read write', 'mcp'];
        yield 'unknown' => ['admin', null];
        yield 'legacy and ability cannot mix' => ['mcp abilities', null];
        yield 'alias and ability cannot mix' => ['read abilities:read', null];
    }

    public function testConsentDistinguishesReadonlyFullAndLegacyGrants(): void
    {
        $read = \Novamira\OAuth\Consent\consent_grant_details('abilities:read');
        self::assertStringContainsString('readonly', strtolower($read['label']));
        self::assertStringContainsString('readonly=true', $read['description']);
        self::assertSame([], $read['risks']);

        $full = \Novamira\OAuth\Consent\consent_grant_details('abilities');
        self::assertStringContainsString('full', strtolower($full['label']));
        self::assertCount(5, $full['risks']);
        self::assertStringContainsString('third-party', $full['description']);
        self::assertStringContainsString('temporary administrator', implode(' ', $full['risks']));

        $legacy = \Novamira\OAuth\Consent\consent_grant_details('mcp');
        self::assertStringContainsString('legacy MCP', $legacy['label']);
    }

    #[DataProvider('grantedScopeProvider')]
    public function testIntrospectionReportsTheActualGrantedScope(mixed $granted, string $expected): void
    {
        self::assertSame(
            $expected,
            \Novamira\OAuth\Endpoints\Introspect\granted_scope_string($granted),
        );
    }

    /** @return iterable<string, array{mixed, string}> */
    public static function grantedScopeProvider(): iterable
    {
        yield 'readonly' => [['abilities:read'], 'abilities:read'];
        yield 'full' => [['abilities'], 'abilities'];
        yield 'legacy' => [['mcp'], 'mcp'];
        yield 'explicit combination' => [['abilities', 'abilities:read'], 'abilities abilities:read'];
        yield 'string input' => ['abilities:read', 'abilities:read'];
        yield 'invalid input' => [null, ''];
    }
}
