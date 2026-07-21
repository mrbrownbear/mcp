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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../includes/oauth/bootstrap.php';
require_once __DIR__ . '/../../includes/oauth/repositories/scope-repository.php';

final class ScopeRepositoryTest extends TestCase
{
    public function testAcceptsAbilityMcpAndCompatibilityAliasScopesOnly(): void
    {
        $repo = new ScopeRepository();
        foreach (['abilities:read', 'abilities', 'mcp', 'read', 'write'] as $scope) {
            self::assertNotNull($repo->getScopeEntityByIdentifier($scope));
        }
        self::assertNull($repo->getScopeEntityByIdentifier('admin'));
        self::assertNull($repo->getScopeEntityByIdentifier(''));
    }

    #[DataProvider('finalizedScopeProvider')]
    public function testFinalizeNeverBroadensTheExplicitGrant(array $requested, array $expected): void
    {
        $repo = new ScopeRepository();
        $client = $this->createMock(ClientEntityInterface::class);

        self::assertSame($expected, $this->ids($repo->finalizeScopes(
            array_map($this->scope(...), $requested),
            'authorization_code',
            $client,
        )));
    }

    /** @return iterable<string, array{list<string>, list<string>}> */
    public static function finalizedScopeProvider(): iterable
    {
        yield 'readonly' => [['abilities:read'], ['abilities:read']];
        yield 'full remains full rather than adding read' => [['abilities'], ['abilities']];
        yield 'explicit ability combination' => [['abilities:read', 'abilities'], ['abilities:read', 'abilities']];
        yield 'mcp' => [['mcp'], ['mcp']];
        yield 'legacy read alias' => [['read'], ['mcp']];
        yield 'legacy write aliases' => [['read', 'write'], ['mcp']];
        yield 'empty legacy default' => [[], ['mcp']];
        yield 'mixed input fails narrow to ability grant' => [['mcp', 'abilities:read'], ['abilities:read']];
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
