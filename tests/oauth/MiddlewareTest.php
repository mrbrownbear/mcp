<?php
// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

if (!function_exists('novamira_current_user_can_manage')) {
    function novamira_current_user_can_manage(): bool
    {
        return (bool) ($GLOBALS['novamira_test_current_user_can_manage'] ?? false);
    }
}
if (!function_exists('home_url')) {
    function home_url(string $path = ''): string
    {
        return ((string) ($GLOBALS['novamira_test_home'] ?? 'https://example.test')) . $path;
    }
}
if (!function_exists('add_filter')) {
    function add_filter(
        string $hook_name,
        callable|string $callback,
        int $priority = 10,
        int $accepted_args = 1,
    ): bool {
        $GLOBALS['novamira_test_filters'][] = [$hook_name, $callback, $priority, $accepted_args];
        return true;
    }
}
if (!function_exists('wp_set_current_user')) {
    function wp_set_current_user(int $user_id): int
    {
        $GLOBALS['novamira_test_current_user_id'] = $user_id;
        return $user_id;
    }
}
if (!function_exists('get_current_user_id')) {
    function get_current_user_id(): int
    {
        return (int) ($GLOBALS['novamira_test_current_user_id'] ?? 0);
    }
}

if (!class_exists('WP_Error')) {
    class WP_Error
    {
        /** @param array<string, mixed> $data */
        public function __construct(
            private string $code = '',
            private string $message = '',
            private array $data = [],
        ) {
        }

        public function get_error_code(): string
        {
            return $this->code;
        }

        public function get_error_message(): string
        {
            return $this->message;
        }

        /** @return array<string, mixed> */
        public function get_error_data(): array
        {
            return $this->data;
        }
    }
}
if (!class_exists('WP_REST_Request')) {
    class WP_REST_Request
    {
        public function __construct(private string $method = 'GET', private string $route = '')
        {
        }

        public function get_route(): string
        {
            return $this->route;
        }

        public function get_method(): string
        {
            return $this->method;
        }
    }
}
if (!class_exists('WP_REST_Response')) {
    class WP_REST_Response
    {
        /** @var array<string, string> */
        public array $headers = [];

        public function __construct(public mixed $data = null, public int $status = 200)
        {
        }

        public function header(string $name, string $value): void
        {
            $this->headers[$name] = $value;
        }
    }
}

if (!defined('ABSPATH')) {
    define('ABSPATH', '/');
}

require_once __DIR__ . '/../../includes/oauth/endpoints/discovery.php';
require_once __DIR__ . '/../../includes/oauth/middleware.php';

final class MiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        $GLOBALS['novamira_test_current_user_can_manage'] = true;
        $GLOBALS['novamira_test_current_user_id'] = 0;
        $GLOBALS['novamira_test_filters'] = [];
        \Novamira\OAuth\Middleware\reset_request_context();
    }

    protected function tearDown(): void
    {
        unset(
            $_GET['rest_route'],
            $_SERVER['REQUEST_URI'],
            $_SERVER['HTTP_AUTHORIZATION'],
            $_SERVER['REDIRECT_HTTP_AUTHORIZATION'],
            $GLOBALS['novamira_test_current_user_can_manage'],
            $GLOBALS['novamira_test_current_user_id'],
            $GLOBALS['novamira_test_filters'],
            $GLOBALS['novamira_test_home'],
        );
        \Novamira\OAuth\Middleware\reset_request_context();
    }

    public function testWwwAuthenticateHeaderAdvertisesTheRootMetadataUrl(): void
    {
        $GLOBALS['novamira_test_home'] = 'https://example.test';
        self::assertSame(
            'Bearer resource_metadata="https://example.test/.well-known/oauth-protected-resource", scope="mcp"',
            \Novamira\OAuth\Middleware\www_authenticate_header(),
        );
    }

    public function testWwwAuthenticateHeaderCarriesTheSubdirectoryPath(): void
    {
        // The centralized URL must stay byte-for-byte what the site advertises: on a subdirectory
        // install the challenge points at /subsite/.well-known/..., which this install serves.
        $GLOBALS['novamira_test_home'] = 'https://example.com/subsite';
        self::assertSame(
            'Bearer resource_metadata="https://example.com/subsite/.well-known/oauth-protected-resource", scope="mcp"',
            \Novamira\OAuth\Middleware\www_authenticate_header(),
        );
    }

    public function testRegistersEarlyIdentityAndAuthoritativeLateAuthorizationHooks(): void
    {
        \Novamira\OAuth\Middleware\register();

        self::assertContains(
            ['determine_current_user', 'Novamira\\OAuth\\Middleware\\resolve_bearer_identity', 30, 1],
            $GLOBALS['novamira_test_filters'],
        );
        self::assertContains(
            ['rest_authentication_errors', 'Novamira\\OAuth\\Middleware\\reject_invalid_bearer', 5, 1],
            $GLOBALS['novamira_test_filters'],
        );
        self::assertContains(
            ['rest_request_before_callbacks', 'Novamira\\OAuth\\Middleware\\authorize_routed_request', 5, 3],
            $GLOBALS['novamira_test_filters'],
        );
    }

    public function testMcpRouteMatchesOnlyTheOauthServer(): void
    {
        self::assertTrue(\Novamira\OAuth\Middleware\is_mcp_route('/mcp/novamira-oauth'));
        self::assertTrue(\Novamira\OAuth\Middleware\is_mcp_route('/mcp/novamira-oauth/tools/list'));
        self::assertFalse(\Novamira\OAuth\Middleware\is_mcp_route('/mcp/novamira'));
        self::assertFalse(\Novamira\OAuth\Middleware\is_mcp_route('/mcp/mcp-adapter-default-server'));
    }

    /** @param array{0: string, 1: string, 2: bool} $case */
    #[DataProvider('abilityRouteProvider')]
    public function testAbilityRouteAllowlistUsesExactRouteAndMethod(array $case): void
    {
        [$method, $route, $allowed] = $case;

        self::assertSame($allowed, \Novamira\OAuth\Middleware\oauth_identity_may_use_route($route, $method));
    }

    /** @return iterable<string, array{array{string, string, bool}}> */
    public static function abilityRouteProvider(): iterable
    {
        yield 'list get' => [['GET', '/wp-abilities/v1/abilities', true]];
        yield 'list head' => [['HEAD', '/wp-abilities/v1/abilities', true]];
        yield 'list post' => [['POST', '/wp-abilities/v1/abilities', false]];
        yield 'item' => [['GET', '/wp-abilities/v1/abilities/novamira/read-file', true]];
        yield 'nested item' => [['GET', '/wp-abilities/v1/abilities/vendor/group/name', true]];
        yield 'item head excluded' => [['HEAD', '/wp-abilities/v1/abilities/novamira/read-file', false]];
        yield 'shim' => [['POST', '/novamira/v1/abilities/novamira/read-file/run', true]];
        yield 'nested shim' => [['POST', '/novamira/v1/abilities/vendor/group/name/run', true]];
        yield 'shim get excluded' => [['GET', '/novamira/v1/abilities/novamira/read-file/run', false]];
        yield 'lookalike excluded' => [['POST', '/novamira/v1/abilities/novamira/read-file/run/extra', false]];
    }

    public function testMissingBearerLeavesWordPressAuthenticationUnchanged(): void
    {
        $called = false;
        $user = \Novamira\OAuth\Middleware\resolve_bearer_identity_using(
            false,
            '',
            static function () use (&$called): array {
                $called = true;
                return ['user_id' => 7, 'scopes' => ['mcp']];
            },
        );

        self::assertFalse($user);
        self::assertFalse($called);
        self::assertNull(\Novamira\OAuth\Middleware\request_authentication_error());
    }

    public function testMalformedBearerIsRejectedWithoutSettingAUser(): void
    {
        $user = \Novamira\OAuth\Middleware\resolve_bearer_identity_using(
            false,
            'Bearer   ',
            static fn(): array => ['user_id' => 7, 'scopes' => ['mcp']],
        );

        self::assertFalse($user);
        self::assertSame(0, get_current_user_id());
        $error = \Novamira\OAuth\Middleware\reject_invalid_bearer(null);
        self::assertInstanceOf(WP_Error::class, $error);
        self::assertSame(401, $error->get_error_data()['status']);
    }

    #[DataProvider('invalidTokenProvider')]
    public function testInvalidExpiredAndRevokedTokensFailClosed(string $kind): void
    {
        $user = \Novamira\OAuth\Middleware\resolve_bearer_identity_using(
            false,
            'Bearer ' . $kind,
            static function () use ($kind): array {
                throw OAuthServerException::accessDenied('Simulated ' . $kind . ' token.');
            },
        );

        self::assertFalse($user);
        self::assertSame(0, get_current_user_id());
        self::assertInstanceOf(WP_Error::class, \Novamira\OAuth\Middleware\request_authentication_error());
    }

    /** @return iterable<string, array{string}> */
    public static function invalidTokenProvider(): iterable
    {
        yield 'invalid signature' => ['invalid'];
        yield 'expired' => ['expired'];
        yield 'revoked' => ['revoked'];
    }

    public function testValidBearerSetsIdentityBeforeRestHardeningRuns(): void
    {
        $user = $this->authenticateOauthUser();

        self::assertSame(73, $user);
        self::assertSame(73, get_current_user_id());
        self::assertTrue($this->hardeningCallbackAllowsOnlyAuthenticatedRequests());
        self::assertNull(\Novamira\OAuth\Middleware\reject_invalid_bearer(null));
    }

    public function testCookieAndApplicationPasswordIdentitiesAreNeverReplaced(): void
    {
        foreach ([41, 42] as $existingUser) {
            $called = false;
            $resolved = \Novamira\OAuth\Middleware\resolve_bearer_identity_using(
                $existingUser,
                'Bearer must-not-be-read',
                static function () use (&$called): array {
                    $called = true;
                    return ['user_id' => 73, 'scopes' => ['mcp']];
                },
            );
            self::assertSame($existingUser, $resolved);
            self::assertFalse($called);
            self::assertNull(\Novamira\OAuth\Middleware\request_oauth_identity());
        }
    }

    public function testQueryParameterCannotSpoofTheAuthoritativeRoute(): void
    {
        $_GET['rest_route'] = '/wp-abilities/v1/abilities';
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts?rest_route=/wp-abilities/v1/abilities';
        $this->authenticateOauthUser();

        $result = \Novamira\OAuth\Middleware\authorize_routed_request(
            new WP_REST_Response(['preempted' => true]),
            null,
            new WP_REST_Request('GET', '/wp/v2/posts'),
        );

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('rest_oauth_route_forbidden', $result->get_error_code());
        self::assertSame(403, $result->get_error_data()['status']);
    }

    #[DataProvider('excludedRouteProvider')]
    public function testValidBearerIsRejectedOutsideTheAllowlist(string $method, string $route): void
    {
        $this->authenticateOauthUser();

        $result = \Novamira\OAuth\Middleware\authorize_routed_request(
            null,
            null,
            new WP_REST_Request($method, $route),
        );

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame('rest_oauth_route_forbidden', $result->get_error_code());
    }

    /** @return iterable<string, array{string, string}> */
    public static function excludedRouteProvider(): iterable
    {
        yield 'upload' => ['POST', '/novamira/v1/upload/example'];
        yield 'temporary administrator' => ['POST', '/novamira/v1/admin-access'];
        yield 'chat' => ['POST', '/novamira/v1/chat'];
        yield 'browser runtime' => ['POST', '/novamira/v1/gutenberg/finalize'];
        yield 'canonical Application Password MCP' => ['POST', '/mcp/novamira'];
        yield 'legacy MCP' => ['POST', '/mcp/mcp-adapter-default-server'];
        yield 'unrelated REST' => ['GET', '/wp/v2/posts'];
    }

    public function testAllowedRouteStillRequiresCurrentManagementPermission(): void
    {
        $this->authenticateOauthUser();
        $GLOBALS['novamira_test_current_user_can_manage'] = false;

        $result = \Novamira\OAuth\Middleware\authorize_routed_request(
            null,
            null,
            new WP_REST_Request('GET', '/wp-abilities/v1/abilities'),
        );

        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame(403, $result->get_error_data()['status']);
    }

    public function testAllowedAbilityRouteAcceptsValidCurrentGrant(): void
    {
        $this->authenticateOauthUser();

        self::assertNull(\Novamira\OAuth\Middleware\authorize_routed_request(
            null,
            null,
            new WP_REST_Request('POST', '/novamira/v1/abilities/novamira/read-file/run'),
        ));
    }

    public function testLegacyMcpGrantRemainsIsolatedToItsExistingEndpoint(): void
    {
        $this->authenticateOauthUser(['mcp']);
        self::assertNull(\Novamira\OAuth\Middleware\authorize_routed_request(
            null,
            null,
            new WP_REST_Request('POST', '/mcp/novamira-oauth'),
        ));

        $result = \Novamira\OAuth\Middleware\authorize_routed_request(
            null,
            null,
            new WP_REST_Request('GET', '/wp-abilities/v1/abilities'),
        );
        self::assertInstanceOf(WP_Error::class, $result);
        self::assertSame(403, $result->get_error_data()['status']);
    }

    public function testChallengeSkipsApplicationPasswordAndLegacyRoutes(): void
    {
        self::assertNull(\Novamira\OAuth\Middleware\challenge_unauthenticated(
            null,
            null,
            new WP_REST_Request('POST', '/mcp/novamira'),
        ));
        self::assertNull(\Novamira\OAuth\Middleware\challenge_unauthenticated(
            null,
            null,
            new WP_REST_Request('POST', '/mcp/mcp-adapter-default-server'),
        ));
    }

    public function testBearerParsingAndChallengeContract(): void
    {
        self::assertTrue(\Novamira\OAuth\Middleware\has_bearer_scheme('Bearer'));
        self::assertTrue(\Novamira\OAuth\Middleware\has_bearer_authorization('bearer abc.def'));
        self::assertFalse(\Novamira\OAuth\Middleware\has_bearer_authorization('Basic abc.def'));
        self::assertSame(
            'Bearer abc.def',
            \Novamira\OAuth\Middleware\normalize_bearer_authorization('bearer abc.def'),
        );

        $challenge = \Novamira\OAuth\Middleware\www_authenticate_header('invalid_token');
        self::assertStringContainsString('resource_metadata=', $challenge);
        self::assertStringContainsString('error="invalid_token"', $challenge);
        self::assertStringContainsString('scope="mcp"', $challenge);
    }

    /** @param list<string> $scopes */
    private function authenticateOauthUser(array $scopes = ['abilities']): mixed
    {
        return \Novamira\OAuth\Middleware\resolve_bearer_identity_using(
            false,
            'Bearer valid-token',
            static fn(): array => ['user_id' => 73, 'scopes' => $scopes],
        );
    }

    private function hardeningCallbackAllowsOnlyAuthenticatedRequests(): bool
    {
        return get_current_user_id() > 0;
    }
}
