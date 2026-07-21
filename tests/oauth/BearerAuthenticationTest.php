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
if (!function_exists('rest_url')) {
    function rest_url(string $path = ''): string
    {
        return 'https://example.test/wp-json/' . ltrim($path, characters: '/');
    }
}

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResourceServer;
use Novamira\OAuth\Repositories\AccessTokenEntity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../includes/oauth/bootstrap.php';
require_once __DIR__ . '/../../includes/oauth/bridge.php';
require_once __DIR__ . '/../../includes/oauth/repositories/access-token-repository.php';
require_once __DIR__ . '/../../includes/oauth/middleware.php';

final class BearerAuthenticationTest extends TestCase
{
    private string $privateKey;
    private string $publicKey;

    protected function setUp(): void
    {
        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($resource);
        $private = '';
        self::assertTrue(openssl_pkey_export($resource, $private));
        $details = openssl_pkey_get_details($resource);
        self::assertIsArray($details);

        $this->privateKey = $private;
        $this->publicKey = (string) $details['key'];
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['HTTPS'] = 'on';
        $_SERVER['HTTP_HOST'] = 'example.test';
        $_SERVER['REQUEST_URI'] = '/wp-json/wp-abilities/v1/abilities';
    }

    protected function tearDown(): void
    {
        unset(
            $_SERVER['REQUEST_METHOD'],
            $_SERVER['HTTPS'],
            $_SERVER['HTTP_HOST'],
            $_SERVER['REQUEST_URI'],
        );
    }

    public function testValidTokenReturnsBoundSubjectAndScopes(): void
    {
        $token = $this->accessToken(new \DateTimeImmutable('+1 hour'));

        self::assertSame(
            ['user_id' => 73, 'scopes' => ['mcp']],
            \Novamira\OAuth\Middleware\validate_bearer_credential(
                'Bearer ' . $token,
                $this->resourceServer(revoked: false),
            ),
        );
    }

    #[DataProvider('invalidCredentialProvider')]
    public function testMalformedExpiredRevokedAndWrongAudienceTokensAreRejected(string $kind): void
    {
        $server = $this->resourceServer(revoked: $kind === 'revoked');
        $token = match ($kind) {
            'malformed' => 'not-a-jwt',
            'expired' => $this->accessToken(new \DateTimeImmutable('-1 hour')),
            'revoked' => $this->accessToken(new \DateTimeImmutable('+1 hour')),
            'wrong audience' => $this->jwtForAudience('https://evil.test/wp-json/mcp/novamira-oauth'),
        };

        $this->expectException(OAuthServerException::class);
        \Novamira\OAuth\Middleware\validate_bearer_credential('Bearer ' . $token, $server);
    }

    /** @return iterable<string, array{string}> */
    public static function invalidCredentialProvider(): iterable
    {
        yield 'malformed' => ['malformed'];
        yield 'expired' => ['expired'];
        yield 'revoked' => ['revoked'];
        yield 'wrong audience' => ['wrong audience'];
    }

    private function accessToken(\DateTimeImmutable $expiry): string
    {
        $entity = new AccessTokenEntity();
        $entity->setPrivateKey(new CryptKey($this->privateKey, passPhrase: null, keyPermissionsCheck: false));
        $entity->setIdentifier('token-' . bin2hex(random_bytes(8)));
        $entity->setUserIdentifier('73');
        $entity->setExpiryDateTime($expiry);
        $entity->addScope($this->scope('mcp'));

        return (string) $entity;
    }

    private function jwtForAudience(string $audience): string
    {
        $configuration = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($this->privateKey),
            InMemory::plainText($this->publicKey),
        );
        $now = new \DateTimeImmutable();
        $token = $configuration
            ->builder()
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt(new \DateTimeImmutable('+1 hour'))
            ->permittedFor($audience)
            ->identifiedBy('wrong-audience-token')
            ->relatedTo('73')
            ->withClaim('scopes', ['mcp'])
            ->getToken($configuration->signer(), $configuration->signingKey());

        return $token->toString();
    }

    private function resourceServer(bool $revoked): ResourceServer
    {
        $repository = new class ($revoked) implements AccessTokenRepositoryInterface {
            public function __construct(private bool $revoked)
            {
            }

            public function getNewToken(
                ClientEntityInterface $clientEntity,
                array $scopes,
                mixed $userIdentifier = null,
            ): AccessTokenEntityInterface {
                throw new LogicException('Not used by resource validation.');
            }

            public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
            {
            }

            public function revokeAccessToken(mixed $tokenId): void
            {
            }

            public function isAccessTokenRevoked(mixed $tokenId): bool
            {
                return $this->revoked;
            }
        };

        return new ResourceServer(
            $repository,
            new CryptKey($this->publicKey, passPhrase: null, keyPermissionsCheck: false),
        );
    }

    private function scope(string $identifier): ScopeEntityInterface
    {
        return new class ($identifier) implements ScopeEntityInterface {
            public function __construct(private string $identifier)
            {
            }

            public function getIdentifier(): string
            {
                return $this->identifier;
            }

            public function jsonSerialize(): mixed
            {
                return $this->identifier;
            }
        };
    }
}
