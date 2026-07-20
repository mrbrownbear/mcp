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

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use Novamira\OAuth\Repositories\ScopeEntity;
use Novamira\OAuth\Repositories\ScopeRepository;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../includes/oauth/bootstrap.php';
require_once __DIR__ . '/../../includes/oauth/repositories/scope-repository.php';

/**
 * The server advertises only the `mcp` scope, but some MCP proxies request the WordPress-ecosystem
 * defaults `read`/`write`. Those are accepted as aliases and every issued token is still granted
 * `mcp`, which is the only scope the middleware admits. Access is all-or-nothing, so the aliases
 * carry no extra privilege.
 */
final class ScopeRepositoryTest extends TestCase
{
    public function testAcceptsMcpAndWordPressAliasesOnly(): void
    {
        $repo = new ScopeRepository();
        self::assertNotNull($repo->getScopeEntityByIdentifier('mcp'));
        self::assertNotNull($repo->getScopeEntityByIdentifier('read'));
        self::assertNotNull($repo->getScopeEntityByIdentifier('write'));
        self::assertNull($repo->getScopeEntityByIdentifier('admin'));
        self::assertNull($repo->getScopeEntityByIdentifier(''));
    }

    public function testFinalizeAlwaysGrantsMcp(): void
    {
        $repo = new ScopeRepository();
        $client = $this->createMock(ClientEntityInterface::class);

        // A read/write request still yields mcp on the token.
        self::assertContains('mcp', $this->ids($repo->finalizeScopes(
            [$this->scope('read'), $this->scope('write')],
            'authorization_code',
            $client,
        )));

        // An mcp request stays exactly mcp (no duplicate).
        self::assertSame(['mcp'], $this->ids($repo->finalizeScopes([$this->scope('mcp')], 'authorization_code', $client)));

        // An empty grant is normalized to mcp.
        self::assertSame(['mcp'], $this->ids($repo->finalizeScopes([], 'authorization_code', $client)));
    }

    private function scope(string $id): ScopeEntity
    {
        $entity = new ScopeEntity();
        $entity->setIdentifier($id);
        return $entity;
    }

    /**
     * @param array<array-key, ScopeEntityInterface> $scopes
     * @return list<string>
     */
    private function ids(array $scopes): array
    {
        return array_values(array_map(static fn(ScopeEntityInterface $s): string => $s->getIdentifier(), $scopes));
    }
}
