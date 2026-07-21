<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace Novamira\OAuth\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\ScopeTrait;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

if (!defined('ABSPATH')) {
    exit();
}

final class ScopeEntity implements ScopeEntityInterface
{
    use EntityTrait;
    use ScopeTrait;
}

// @mago-expect lint:single-class-per-file
final class ScopeRepository implements ScopeRepositoryInterface
{
    public function getScopeEntityByIdentifier(mixed $identifier): ?ScopeEntityInterface
    {
        $identifier = (string) $identifier;
        if (!in_array($identifier, \Novamira\OAuth\supported_scopes(), strict: true)) {
            return null;
        }
        $entity = new ScopeEntity();
        $entity->setIdentifier($identifier);
        return $entity;
    }

    /** @param array<array-key, ScopeEntityInterface> $scopes */
    public function finalizeScopes(
        array $scopes,
        mixed $grantType,
        ClientEntityInterface $clientEntity,
        mixed $userIdentifier = null,
    ): array {
        $granted = array_values(array_filter($scopes, static fn(ScopeEntityInterface $s): bool => in_array(
            $s->getIdentifier(),
            \Novamira\OAuth\supported_scopes(),
            strict: true,
        )));

        $ability_grants = array_values(array_filter($granted, static fn(ScopeEntityInterface $scope): bool => in_array(
            $scope->getIdentifier(),
            ['abilities:read', 'abilities'],
            strict: true,
        )));
        if ($ability_grants !== []) {
            // `abilities` semantically includes read access, but the explicit grant remains unchanged.
            return $ability_grants;
        }

        // Preserve the old read/write alias behavior only for legacy authorization flows.
        $mcp = new ScopeEntity();
        $mcp->setIdentifier('mcp');
        return [$mcp];
    }
}
