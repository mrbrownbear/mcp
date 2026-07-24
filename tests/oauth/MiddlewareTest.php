<?php
// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

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

if (!class_exists('WP_REST_Request')) {
    // Minimal stand-in: challenge_unauthenticated() only reads get_route() before it decides
    // whether the request is in the OAuth scope.
    class WP_REST_Request
    {
        public function __construct(private string $route = '')
        {
        }

        public function get_route(): string
        {
            return $this->route;
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
    protected function tearDown(): void
    {
        unset(
            $_GET['rest_route'],
            $_SERVER['REQUEST_URI'],
            $_SERVER['HTTP_AUTHORIZATION'],
            $_SERVER['REDIRECT_HTTP_AUTHORIZATION'],
            $GLOBALS['novamira_test_current_user_can_manage'],
            $GLOBALS['novamira_test_home'],
        );
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

    public function testMcpRouteMatchesOnlyTheOauthServer(): void
    {
        self::assertTrue(\Novamira\OAuth\Middleware\is_mcp_route('/mcp/novamira-oauth'));
        self::assertTrue(\Novamira\OAuth\Middleware\is_mcp_route('/mcp/novamira-oauth/tools/list'));
        self::assertFalse(\Novamira\OAuth\Middleware\is_mcp_route('/wp/v2/posts'));
    }

    public function testCanonicalAndLegacyRoutesAreOutsideOauthScope(): void
    {
        // The Application Password endpoint and its legacy alias must never be treated as OAuth
        // routes, or the challenge below would 401 the existing app-password connections.
        self::assertFalse(\Novamira\OAuth\Middleware\is_mcp_route('/mcp/novamira'));
        self::assertFalse(\Novamira\OAuth\Middleware\is_mcp_route('/mcp/novamira/tools/list'));
        self::assertFalse(\Novamira\OAuth\Middleware\is_mcp_route('/mcp/mcp-adapter-default-server'));
    }

    public function testChallengeSkipsCanonicalAndLegacyRoutes(): void
    {
        // A request to the Application Password endpoint (or its legacy alias) is outside the OAuth
        // route scope, so the challenge returns null and never emits a 401 OAuth challenge — an
        // app-password client keeps authenticating through WordPress core as before.
        self::assertNull(
            \Novamira\OAuth\Middleware\challenge_unauthenticated(null, null, new WP_REST_Request('/mcp/novamira')),
        );
        self::assertNull(
            \Novamira\OAuth\Middleware\challenge_unauthenticated(
                null,
                null,
                new WP_REST_Request('/mcp/mcp-adapter-default-server'),
            ),
        );
    }

    public function testPrettyMcpRestUrlTargetsMcpRoute(): void
    {
        $_SERVER['REQUEST_URI'] = '/wp-json/mcp/novamira-oauth/tools/list';

        self::assertTrue(\Novamira\OAuth\Middleware\request_targets_mcp_route());
    }

    public function testQueryRestRouteTargetsMcpRoute(): void
    {
        $_GET['rest_route'] = '/mcp/novamira-oauth';
        $_SERVER['REQUEST_URI'] = '/?rest_route=%2Fmcp%2Fnovamira-oauth';

        self::assertTrue(\Novamira\OAuth\Middleware\request_targets_mcp_route());
    }

    public function testCanonicalPrettyUrlDoesNotTargetOauthRoute(): void
    {
        // The Bearer authenticator gates on this too, so the canonical app-password endpoint must
        // read as outside the OAuth route scope.
        $_SERVER['REQUEST_URI'] = '/wp-json/mcp/novamira/tools/list';

        self::assertFalse(\Novamira\OAuth\Middleware\request_targets_mcp_route());
    }

    public function testNonMcpRestUrlDoesNotTargetMcpRoute(): void
    {
        $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';

        self::assertFalse(\Novamira\OAuth\Middleware\request_targets_mcp_route());
    }

    public function testBearerSchemeIsCaseInsensitive(): void
    {
        self::assertTrue(\Novamira\OAuth\Middleware\has_bearer_authorization('Bearer abc.def'));
        self::assertTrue(\Novamira\OAuth\Middleware\has_bearer_authorization('bearer abc.def'));
        self::assertFalse(\Novamira\OAuth\Middleware\has_bearer_authorization('Basic abc.def'));
    }

    public function testBearerAuthorizationIsNormalizedForLeagueParser(): void
    {
        self::assertSame(
            'Bearer abc.def',
            \Novamira\OAuth\Middleware\normalize_bearer_authorization('bearer abc.def'),
        );
    }

    public function testWwwAuthenticateChallengeDeclaresScope(): void
    {
        $challenge = \Novamira\OAuth\Middleware\www_authenticate_header();

        self::assertStringStartsWith('Bearer ', $challenge);
        self::assertStringContainsString('resource_metadata=', $challenge);
        self::assertStringContainsString('scope="mcp"', $challenge);
        self::assertStringNotContainsString('error=', $challenge);
    }

    public function testWwwAuthenticateCarriesTheErrorCode(): void
    {
        $invalid = \Novamira\OAuth\Middleware\www_authenticate_header('invalid_token');

        self::assertStringContainsString('error="invalid_token"', $invalid);
        self::assertStringContainsString('scope="mcp"', $invalid);
    }

    public function testMcpScopeIsRequired(): void
    {
        self::assertTrue(\Novamira\OAuth\Middleware\has_mcp_scope(['profile', 'mcp']));
        self::assertTrue(\Novamira\OAuth\Middleware\has_mcp_scope('profile mcp'));
        self::assertFalse(\Novamira\OAuth\Middleware\has_mcp_scope(['profile']));
        self::assertFalse(\Novamira\OAuth\Middleware\has_mcp_scope(null));
    }

    public function testCurrentUserMustStillManageNovamira(): void
    {
        $GLOBALS['novamira_test_current_user_can_manage'] = false;

        self::assertFalse(\Novamira\OAuth\Middleware\current_user_can_access_mcp());
    }

    public function testCurrentManagerCanUseOAuthMcp(): void
    {
        $GLOBALS['novamira_test_current_user_can_manage'] = true;

        self::assertTrue(\Novamira\OAuth\Middleware\current_user_can_access_mcp());
    }
}
