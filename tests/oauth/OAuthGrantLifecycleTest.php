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

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Novamira\OAuth\Repositories\AccessTokenEntity;
use Novamira\OAuth\Repositories\AuthCodeEntity;
use Novamira\OAuth\Repositories\ClientEntity;
use Novamira\OAuth\Repositories\RefreshTokenEntity;
use Novamira\OAuth\Repositories\ScopeRepository;
use Novamira\OAuth\Repositories\UserEntity;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../includes/oauth/bootstrap.php';
require_once __DIR__ . '/../../includes/oauth/repositories/client-repository.php';
require_once __DIR__ . '/../../includes/oauth/repositories/access-token-repository.php';
require_once __DIR__ . '/../../includes/oauth/repositories/auth-code-repository.php';
require_once __DIR__ . '/../../includes/oauth/repositories/refresh-token-repository.php';
require_once __DIR__ . '/../../includes/oauth/repositories/scope-repository.php';
require_once __DIR__ . '/../../includes/oauth/repositories/user-repository.php';

final class OAuthGrantLifecycleTest extends TestCase
{
    #[DataProvider('abilityScopeProvider')]
    public function testAuthorizationCodeIssuanceAndRefreshPreserveTheGrant(string $scope): void
    {
        $harness = $this->serverHarness();
        $tokens = $this->authorizeAndExchange($harness['server'], $scope);

        self::assertSame([$scope], $this->jwtScopes($tokens['access_token']));
        $refreshed = $this->refresh($harness['server'], $tokens['refresh_token']);
        self::assertSame([$scope], $this->jwtScopes($refreshed['access_token']));
    }

    /** @return iterable<string, array{string}> */
    public static function abilityScopeProvider(): iterable
    {
        yield 'readonly' => ['abilities:read'];
        yield 'full' => ['abilities'];
        yield 'legacy' => ['mcp'];
    }

    public function testRefreshCannotBroadenReadonlyGrant(): void
    {
        $harness = $this->serverHarness();
        $tokens = $this->authorizeAndExchange($harness['server'], 'abilities:read');

        $this->expectException(OAuthServerException::class);
        $this->refresh($harness['server'], $tokens['refresh_token'], scope: 'abilities');
    }

    /**
     * @return array{
     *     server: AuthorizationServer,
     *     access: AccessTokenRepositoryInterface,
     *     refresh: RefreshTokenRepositoryInterface,
     *     auth_code: AuthCodeRepositoryInterface
     * }
     */
    private function serverHarness(): array
    {
        $client = new ClientEntity();
        $client->setIdentifier('public-client');
        $client->setName('Novamira CLI');
        $client->setRedirectUri(['http://127.0.0.1/callback']);
        $client->setIsConfidential(false);

        $clients = new class ($client) implements ClientRepositoryInterface {
            public function __construct(private ClientEntityInterface $client)
            {
            }

            public function getClientEntity(mixed $clientIdentifier): ?ClientEntityInterface
            {
                return $clientIdentifier === $this->client->getIdentifier() ? $this->client : null;
            }

            public function validateClient(mixed $clientIdentifier, mixed $clientSecret, mixed $grantType): bool
            {
                return $clientIdentifier === $this->client->getIdentifier();
            }
        };

        $access = new class implements AccessTokenRepositoryInterface {
            /** @var array<string, bool> */
            private array $revoked = [];

            public function getNewToken(
                ClientEntityInterface $clientEntity,
                array $scopes,
                mixed $userIdentifier = null,
            ): AccessTokenEntityInterface {
                $token = new AccessTokenEntity();
                $token->setClient($clientEntity);
                foreach ($scopes as $scope) {
                    $token->addScope($scope);
                }
                $token->setUserIdentifier($userIdentifier);
                return $token;
            }

            public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
            {
                $this->revoked[$accessTokenEntity->getIdentifier()] = false;
            }

            public function revokeAccessToken(mixed $tokenId): void
            {
                $this->revoked[(string) $tokenId] = true;
            }

            public function isAccessTokenRevoked(mixed $tokenId): bool
            {
                return $this->revoked[(string) $tokenId] ?? true;
            }
        };

        $authCodes = new class implements AuthCodeRepositoryInterface {
            /** @var array<string, bool> */
            private array $revoked = [];

            public function getNewAuthCode(): AuthCodeEntityInterface
            {
                return new AuthCodeEntity();
            }

            public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
            {
                $this->revoked[$authCodeEntity->getIdentifier()] = false;
            }

            public function revokeAuthCode(mixed $codeId): void
            {
                $this->revoked[(string) $codeId] = true;
            }

            public function isAuthCodeRevoked(mixed $codeId): bool
            {
                return $this->revoked[(string) $codeId] ?? true;
            }
        };

        $refresh = new class implements RefreshTokenRepositoryInterface {
            /** @var array<string, bool> */
            private array $revoked = [];

            public function getNewRefreshToken(): ?RefreshTokenEntityInterface
            {
                return new RefreshTokenEntity();
            }

            public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
            {
                $this->revoked[$refreshTokenEntity->getIdentifier()] = false;
            }

            public function revokeRefreshToken(mixed $tokenId): void
            {
                $this->revoked[(string) $tokenId] = true;
            }

            public function isRefreshTokenRevoked(mixed $tokenId): bool
            {
                return $this->revoked[(string) $tokenId] ?? true;
            }
        };

        $keyResource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($keyResource);
        $privatePem = '';
        self::assertTrue(openssl_pkey_export($keyResource, $privatePem));
        $privateKey = new CryptKey($privatePem, passPhrase: null, keyPermissionsCheck: false);
        $encryptionKey = base64_encode(random_bytes(32));

        $server = new AuthorizationServer($clients, $access, new ScopeRepository(), $privateKey, $encryptionKey);
        $authCodeGrant = new AuthCodeGrant($authCodes, $refresh, new DateInterval('PT2M'));
        $authCodeGrant->setRefreshTokenTTL(new DateInterval('PT1H'));
        $server->enableGrantType($authCodeGrant, new DateInterval('PT1H'));
        $refreshGrant = new RefreshTokenGrant($refresh);
        $refreshGrant->setRefreshTokenTTL(new DateInterval('PT1H'));
        $server->enableGrantType($refreshGrant, new DateInterval('PT1H'));

        return ['server' => $server, 'access' => $access, 'refresh' => $refresh, 'auth_code' => $authCodes];
    }

    /** @return array{access_token: string, refresh_token: string} */
    private function authorizeAndExchange(AuthorizationServer $server, string $scope): array
    {
        $verifier = str_repeat('v', 64);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, binary: true)), '+/', '-_'), '=');
        $redirectUri = 'http://127.0.0.1/callback';
        $authorization = (new ServerRequest('GET', 'https://example.test/authorize'))->withQueryParams([
            'response_type' => 'code',
            'client_id' => 'public-client',
            'redirect_uri' => $redirectUri,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'scope' => $scope,
            'state' => 'state-value',
        ]);
        $validated = $server->validateAuthorizationRequest($authorization);
        $user = new UserEntity();
        $user->setIdentifier('73');
        $validated->setUser($user);
        $validated->setAuthorizationApproved(true);
        $response = $server->completeAuthorizationRequest($validated, (new Psr17Factory())->createResponse());

        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $redirectQuery);
        $code = (string) ($redirectQuery['code'] ?? '');
        self::assertNotSame('', $code);

        $request = (new ServerRequest('POST', 'https://example.test/token'))->withParsedBody([
            'grant_type' => 'authorization_code',
            'client_id' => 'public-client',
            'redirect_uri' => $redirectUri,
            'code' => $code,
            'code_verifier' => $verifier,
        ]);
        $tokenResponse = $server->respondToAccessTokenRequest($request, (new Psr17Factory())->createResponse());
        return $this->tokenBody((string) $tokenResponse->getBody());
    }

    /** @return array{access_token: string, refresh_token: string} */
    private function refresh(AuthorizationServer $server, string $refreshToken, ?string $scope = null): array
    {
        $body = [
            'grant_type' => 'refresh_token',
            'client_id' => 'public-client',
            'refresh_token' => $refreshToken,
        ];
        if ($scope !== null) {
            $body['scope'] = $scope;
        }
        $request = (new ServerRequest('POST', 'https://example.test/token'))->withParsedBody($body);
        $response = $server->respondToAccessTokenRequest($request, (new Psr17Factory())->createResponse());
        return $this->tokenBody((string) $response->getBody());
    }

    /** @return array{access_token: string, refresh_token: string} */
    private function tokenBody(string $json): array
    {
        $body = json_decode($json, associative: true);
        self::assertIsArray($body);
        self::assertIsString($body['access_token'] ?? null);
        self::assertIsString($body['refresh_token'] ?? null);
        return ['access_token' => $body['access_token'], 'refresh_token' => $body['refresh_token']];
    }

    /** @return list<string> */
    private function jwtScopes(string $jwt): array
    {
        $parts = explode('.', $jwt);
        $json = base64_decode(strtr($parts[1] ?? '', '-_', '+/'), strict: false);
        $payload = json_decode((string) $json, associative: true);
        self::assertIsArray($payload);
        $scopes = $payload['scopes'] ?? null;
        self::assertIsArray($scopes);
        return array_values(array_map(static fn(mixed $scope): string => (string) $scope, $scopes));
    }
}
