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
if (!function_exists('register_rest_route')) {
    function register_rest_route(string $route_namespace, string $route, array $args): bool
    {
        $GLOBALS['novamira_test_rest_routes'][] = [$route_namespace, $route, $args];
        return true;
    }
}
if (!function_exists('novamira_is_enabled')) {
    function novamira_is_enabled(): bool
    {
        return (bool) ($GLOBALS['novamira_test_enabled'] ?? false);
    }
}
if (!function_exists('novamira_current_user_can_manage')) {
    function novamira_current_user_can_manage(): bool
    {
        return (bool) ($GLOBALS['novamira_test_current_user_can_manage'] ?? false);
    }
}
if (!class_exists('WP_REST_Server')) {
    class WP_REST_Server
    {
        public const CREATABLE = 'POST';
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
if (!class_exists('WP_Ability')) {
    class WP_Ability
    {
        /** @param array<string, mixed> $meta */
        public function __construct(private array $meta, private mixed $result = null)
        {
        }

        public function get_meta_item(string $key, mixed $default = null): mixed
        {
            return $this->meta[$key] ?? $default;
        }

        public function execute(mixed $input = null): mixed
        {
            return $this->result instanceof Closure ? ($this->result)($input) : $this->result;
        }
    }
}
if (!function_exists('wp_get_ability')) {
    function wp_get_ability(string $name): mixed
    {
        return $GLOBALS['novamira_test_abilities'][$name] ?? null;
    }
}
if (!class_exists('WP_REST_Request')) {
    class WP_REST_Request implements ArrayAccess
    {
        /** @param array<string, mixed>|null $json */
        public function __construct(
            private string $method = 'GET',
            private string $route = '',
            private string $body = '',
            private ?array $json = null,
            private array $params = [],
        ) {
        }

        public function get_route(): string
        {
            return $this->route;
        }

        public function get_method(): string
        {
            return $this->method;
        }

        public function get_body(): string
        {
            return $this->body;
        }

        /** @return array<string, mixed>|null */
        public function get_json_params(): ?array
        {
            return $this->json;
        }

        public function offsetExists(mixed $offset): bool
        {
            return is_string($offset) && array_key_exists($offset, $this->params);
        }

        public function offsetGet(mixed $offset): mixed
        {
            return is_string($offset) ? ($this->params[$offset] ?? null) : null;
        }

        public function offsetSet(mixed $offset, mixed $value): void
        {
            if (is_string($offset)) {
                $this->params[$offset] = $value;
            }
        }

        public function offsetUnset(mixed $offset): void
        {
            if (is_string($offset)) {
                unset($this->params[$offset]);
            }
        }
    }
}

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../includes/rest-shim.php';

final class RestAbilitySurfaceTest extends TestCase
{
    protected function setUp(): void
    {
        $GLOBALS['novamira_test_enabled'] = true;
        $GLOBALS['novamira_test_current_user_can_manage'] = true;
        $GLOBALS['novamira_test_rest_routes'] = [];
        $GLOBALS['novamira_test_abilities'] = [];
    }

    protected function tearDown(): void
    {
        unset(
            $GLOBALS['novamira_test_enabled'],
            $GLOBALS['novamira_test_current_user_can_manage'],
            $GLOBALS['novamira_test_rest_routes'],
            $GLOBALS['novamira_test_abilities'],
        );
    }

    public function testRegistersCompleteAbilityNameAndInputSchema(): void
    {
        novamira_register_ability_run_rest_shim();

        self::assertCount(1, $GLOBALS['novamira_test_rest_routes']);
        [$namespace, $route, $args] = $GLOBALS['novamira_test_rest_routes'][0];
        self::assertSame('novamira/v1', $namespace);
        self::assertStringContainsString('(?P<ability_name>', $route);
        self::assertArrayHasKey('input', $args['args']);
        self::assertFalse($args['args']['input']['required']);
        self::assertSame('^[a-z0-9-]+(?:/[a-z0-9-]+)+$', $args['args']['ability_name']['pattern']);
    }

    #[DataProvider('validBodyProvider')]
    public function testBodyContractAcceptsOnlyObjectWithArbitraryInput(
        string $raw,
        ?array $json,
        mixed $expected,
    ): void {
        $request = new WP_REST_Request('POST', '/run', $raw, $json);
        self::assertSame($expected, novamira_rest_run_input($request));
    }

    /** @return iterable<string, array{string, array<string, mixed>|null, mixed}> */
    public static function validBodyProvider(): iterable
    {
        yield 'empty body' => ['', null, null];
        yield 'empty object' => ['{}', [], null];
        yield 'null input' => ['{"input":null}', ['input' => null], null];
        yield 'object input' => ['{"input":{"key":"value"}}', ['input' => ['key' => 'value']], ['key' => 'value']];
        yield 'array input' => ['{"input":[1,2]}', ['input' => [1, 2]], [1, 2]];
        yield 'scalar input' => ['{"input":"value"}', ['input' => 'value'], 'value'];
        yield 'boolean input' => ['{"input":false}', ['input' => false], false];
    }

    #[DataProvider('invalidBodyProvider')]
    public function testBodyContractRejectsInvalidTopLevelAndUnexpectedFields(string $raw, ?array $json): void
    {
        $error = novamira_rest_run_input(new WP_REST_Request('POST', '/run', $raw, $json));
        self::assertInstanceOf(WP_Error::class, $error);
        self::assertSame(400, $error->get_error_data()['status']);
    }

    /** @return iterable<string, array{string, array<string, mixed>|null}> */
    public static function invalidBodyProvider(): iterable
    {
        yield 'top-level array' => ['[1,2]', [1, 2]];
        yield 'top-level scalar' => ['"value"', null];
        yield 'malformed object' => ['{"input":', null];
        yield 'extra field' => ['{"input":null,"extra":true}', ['input' => null, 'extra' => true]];
        yield 'only unexpected field' => ['{"extra":true}', ['extra' => true]];
    }

    #[DataProvider('rawResultProvider')]
    public function testExecutionPreservesEveryRawSuccessType(mixed $result): void
    {
        $GLOBALS['novamira_test_abilities']['vendor/group/nested'] = new WP_Ability(
            ['show_in_rest' => true],
            $result,
        );
        $request = new WP_REST_Request(
            'POST',
            '/run',
            '{}',
            [],
            ['ability_name' => 'vendor/group/nested'],
        );

        self::assertSame($result, novamira_rest_run_ability($request));
    }

    /** @return iterable<string, array{mixed}> */
    public static function rawResultProvider(): iterable
    {
        yield 'scalar' => ['value'];
        yield 'array' => [[1, 2]];
        yield 'object' => [(object) ['key' => 'value']];
        yield 'boolean' => [true];
        yield 'null' => [null];
    }

    public function testHiddenMissingAndInvalidAbilityNamesFailSafely(): void
    {
        $GLOBALS['novamira_test_abilities']['vendor/hidden'] = new WP_Ability(['show_in_rest' => false]);

        $hidden = novamira_rest_run_ability($this->requestFor('vendor/hidden'));
        self::assertSame('novamira_ability_hidden', $hidden->get_error_code());
        self::assertSame(404, $hidden->get_error_data()['status']);

        $missing = novamira_rest_run_ability($this->requestFor('vendor/missing'));
        self::assertSame('novamira_ability_not_found', $missing->get_error_code());

        $invalid = novamira_rest_run_ability($this->requestFor('Vendor/invalid_name'));
        self::assertSame('novamira_invalid_ability_name', $invalid->get_error_code());
        self::assertSame(400, $invalid->get_error_data()['status']);
    }

    #[DataProvider('classifiedErrorProvider')]
    public function testClassifiesOnlyStableInputAndPermissionErrors(string $code, int $status): void
    {
        $GLOBALS['novamira_test_abilities']['vendor/error'] = new WP_Ability(
            ['show_in_rest' => true],
            new WP_Error($code, 'Failure'),
        );

        $error = novamira_rest_run_ability($this->requestFor('vendor/error'));
        self::assertInstanceOf(WP_Error::class, $error);
        self::assertSame($code, $error->get_error_code());
        self::assertSame($status, $error->get_error_data()['status']);
    }

    /** @return iterable<string, array{string, int}> */
    public static function classifiedErrorProvider(): iterable
    {
        yield 'invalid input' => ['ability_invalid_input', 400];
        yield 'missing schema' => ['ability_missing_input_schema', 400];
        yield 'permission' => ['ability_invalid_permissions', 403];
    }

    public function testPermissionBoundaryPreservesDisabledAndCapabilityChecks(): void
    {
        $GLOBALS['novamira_test_enabled'] = false;
        $disabled = novamira_rest_run_ability_permission();
        self::assertInstanceOf(WP_Error::class, $disabled);
        self::assertSame('novamira_disabled', $disabled->get_error_code());

        $GLOBALS['novamira_test_enabled'] = true;
        $GLOBALS['novamira_test_current_user_can_manage'] = false;
        $forbidden = novamira_rest_run_ability_permission();
        self::assertInstanceOf(WP_Error::class, $forbidden);
        self::assertSame('novamira_forbidden', $forbidden->get_error_code());
    }

    private function requestFor(string $abilityName): WP_REST_Request
    {
        return new WP_REST_Request('POST', '/run', '{}', [], ['ability_name' => $abilityName]);
    }
}
