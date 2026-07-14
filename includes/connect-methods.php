<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

// Standalone-testable: allow require under PHP CLI without a WordPress bootstrap.
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') {
    exit();
}

/**
 * True when an IPv4/IPv6 literal is in a private, loopback, link-local, or reserved range.
 */
function novamira_ip_is_private_or_loopback(string $ip): bool
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        // Fails validation (=== false) exactly when the address is private or reserved.
        return (
            filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)
            === false
        );
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        $lower = strtolower($ip);
        return (
            $lower === '::1'
            || str_starts_with($lower, 'fe80:')
            || str_starts_with($lower, 'fc')
            || str_starts_with($lower, 'fd')
        );
    }
    return false;
}

/**
 * True when a host is only reachable from the local machine and never from the public
 * internet: single-label hosts, private/loopback IP literals, and local-dev suffixes.
 * Expects a bare host without a port.
 */
function novamira_host_is_local_only(string $host): bool
{
    $host = strtolower(trim($host));
    $host = trim($host, characters: '[]');
    if ($host === '') {
        return false;
    }

    // IP literal → private/loopback ranges are local-only.
    $ip = filter_var($host, FILTER_VALIDATE_IP);
    if ($ip !== false) {
        return novamira_ip_is_private_or_loopback($ip);
    }

    // Single-label host (no dot), e.g. "localhost" or "wordpress".
    if (!str_contains($host, '.')) {
        return true;
    }

    /** @var array<int, string> $suffixes */
    $suffixes = apply_filters('novamira_local_only_host_patterns', [
        '.local',
        '.test',
        '.localhost',
        '.ddev.site',
        '.lndo.site',
    ]);
    foreach ($suffixes as $suffix) {
        if ($suffix !== '' && str_ends_with($host, $suffix)) {
            return true;
        }
    }

    return false;
}

/**
 * True when this site's host cannot be reached from Anthropic's cloud, so a native remote
 * connector will not work and the OAuth flow must run through a local stdio bridge.
 */
function novamira_host_unreachable_from_cloud(): bool
{
    $host = (string) wp_parse_url(home_url(), PHP_URL_HOST);
    return novamira_host_is_local_only($host);
}

/**
 * True when it is safe to run the OAuth flow: the site is served over HTTPS, or WordPress reports a
 * local environment. On a plain-HTTP site the authorization code and the bearer tokens travel in
 * cleartext (RFC 6749/6750 require TLS), and "not reachable from the public internet" is not enough
 * on its own: a private-IP or *.local/*.test host still shares a LAN wire another device can sniff.
 * So HTTP is allowed only when wp_get_environment_type() is 'local' — the same transport policy
 * wp_is_application_passwords_supported() applies. Keyed off the canonical home_url() scheme, not
 * is_ssl(), so a TLS-terminating reverse proxy (https to the public, http to PHP) is not misjudged.
 */
function novamira_oauth_transport_allowed(): bool
{
    if (str_starts_with(strtolower(home_url()), 'https://')) {
        return true;
    }
    return wp_get_environment_type() === 'local';
}

/**
 * Build the Claude "add custom connector" prefill link. Opens the dialog with the name and
 * URL pre-filled; the user still reviews and confirms. No secret is embedded.
 */
function novamira_build_connector_install_link(string $mcp_url, string $connector_name): string
{
    return (
        'https://claude.ai/customize/connectors?modal=add-custom-connector'
        . '&connectorName='
        . rawurlencode($connector_name)
        . '&connectorUrl='
        . rawurlencode($mcp_url)
    );
}

/**
 * Human-readable connector name shown in Claude. Empty site name falls back to "Novamira".
 */
function novamira_build_connector_display_name(string $site_name): string
{
    $site_name = trim($site_name);
    return $site_name !== '' ? 'Novamira - ' . $site_name : 'Novamira';
}

/**
 * npx mcp-remote stdio bridge server object. The bridge runs the OAuth browser flow on behalf
 * of clients that do not perform it natively. $env carries the self-signed TLS bypass on local
 * sites and is empty on public ones.
 *
 * @param array<string, string> $env
 * @return array<string, mixed>
 */
function novamira_oauth_bridge_server(string $mcp_url, array $env): array
{
    $server = ['command' => 'npx', 'args' => ['-y', 'mcp-remote', $mcp_url]];
    if ($env !== []) {
        $server['env'] = $env;
    }
    return $server;
}

/**
 * Wrap a per-client server object in its JSON envelope (mcpServers or servers).
 *
 * @param array<string, mixed> $server
 */
function novamira_oauth_json(string $wrapper, string $mcp_name, array $server): string
{
    return (string) json_encode([$wrapper => [$mcp_name => $server]], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

/**
 * Build a plain code-snippet client entry (no shell, no connector button).
 *
 * @param array<string, string> $paths
 * @return array<string, mixed>
 */
function novamira_oauth_code_entry(string $code, string $hint, array $paths): array
{
    return ['kind' => 'code', 'code' => $code, 'hint' => $hint, 'paths' => $paths, 'isShell' => false];
}

/**
 * "Add to <code>file</code>." hint, shared by the client config entries.
 */
function novamira_oauth_add_to(string $file): string
{
    /* translators: %s: config file name wrapped in <code> tags */
    return sprintf(__('Add to %s.', domain: 'novamira'), '<code>' . $file . '</code>');
}

/**
 * Codex config.toml snippet for the mcp-remote bridge (stdio launch, optional env block).
 *
 * @param array<string, string> $env
 */
function novamira_oauth_bridge_codex(string $mcp_name, string $mcp_url, array $env): string
{
    $tq = static fn(string $v): string => '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $v) . '"';
    $lines = [
        '[mcp_servers.' . $mcp_name . ']',
        'command = "npx"',
        'args = ["-y", "mcp-remote", ' . $tq($mcp_url) . ']',
    ];
    if ($env !== []) {
        $lines[] = '';
        $lines[] = '[mcp_servers.' . $mcp_name . '.env]';
        foreach ($env as $key => $value) {
            $lines[] = $key . ' = ' . $tq($value);
        }
    }
    return implode("\n", $lines);
}

/**
 * `claude mcp add` command for the mcp-remote bridge (stdio launch, optional --env flags).
 *
 * @param array<string, string> $env
 */
function novamira_oauth_bridge_claude_code(string $mcp_name, string $mcp_url, array $env): string
{
    $sq = static fn(string $v): string => "'" . str_replace(search: "'", replace: "'\\''", subject: $v) . "'";
    $parts = ['claude mcp add ' . $sq($mcp_name)];
    foreach ($env as $key => $value) {
        $parts[] = '--env ' . $key . '=' . $sq($value);
    }
    $parts[] = '-- npx -y mcp-remote ' . $sq($mcp_url);
    return implode(" \\\n  ", $parts);
}

/**
 * OAuth per-client connection configs, mirroring the app-password client list.
 *
 * On a publicly reachable site each client gets its native remote-MCP form (a URL the client
 * connects to and runs OAuth against itself), except a tail of clients whose native OAuth flow
 * is not verified, which fall back to the mcp-remote stdio bridge. On a local site every client
 * uses the bridge (which also carries the self-signed TLS bypass), and the browser-only
 * Claude.ai target is omitted because a local URL is unreachable for it.
 *
 * @return array<string, array<string, mixed>>
 */
function novamira_build_oauth_configs(string $mcp_url, string $mcp_name): array
{
    // The TLS-verification bypass rides along only for a self-signed local certificate, the same
    // condition the app-password flow uses; a plain-HTTP local site or a trusted cert needs no flag.
    $env = novamira_likely_self_signed_https() ? ['NODE_TLS_REJECT_UNAUTHORIZED' => '0'] : [];
    if (novamira_host_unreachable_from_cloud()) {
        return novamira_build_oauth_bridge_configs($mcp_url, $mcp_name, $env);
    }
    return novamira_build_oauth_public_configs($mcp_url, $mcp_name);
}

/**
 * Public site: native form per client, with the mcp-remote bridge as the fallback for the tail
 * of clients whose native OAuth flow is not verified. A public host has a trusted certificate,
 * so the bridge needs no TLS bypass.
 *
 * @return array<string, array<string, mixed>>
 */
function novamira_build_oauth_public_configs(string $mcp_url, string $mcp_name): array
{
    $bridge = novamira_build_oauth_bridge_configs($mcp_url, $mcp_name, []);
    $tail = ['antigravity', 'cline', 'roo-code', 'amazon-q', 'zed', 'kilo-code', 'opencode'];

    return array_merge(
        array_intersect_key($bridge, array_flip($tail)),
        novamira_build_oauth_native_configs($mcp_url, $mcp_name),
    );
}

/**
 * Manual walkthrough for the Claude connector clients, which add remote MCP servers from the
 * Connectors UI rather than a config file. The server name keeps the placeholder that the page
 * script swaps for the live name.
 *
 * @return list<array<string, string>>
 */
function novamira_oauth_connector_steps(string $app_label, string $mcp_name, string $mcp_url): array
{
    return [
        [
            'title' => __('Open Connectors', domain: 'novamira'),
            /* translators: %s: the client name, e.g. Claude Desktop */
            'body' => sprintf(__('In %s, open Settings and go to Connectors.', domain: 'novamira'), $app_label),
        ],
        [
            'title' => __('Add a custom connector', domain: 'novamira'),
            'body' => __(
                'Click "Add custom connector" and give it this name, or one you’ll recognize with "Novamira" in it:',
                domain: 'novamira',
            ),
            'copy' => $mcp_name,
        ],
        [
            'title' => __('Enter the server URL', domain: 'novamira'),
            'body' => __(
                'Paste the URL below and save. Leave the OAuth Client ID and Secret (under Advanced settings) empty, then sign in when the browser opens.',
                domain: 'novamira',
            ),
            'copy' => $mcp_url,
        ],
    ];
}

/**
 * Native remote configs for clients that run the OAuth flow themselves. Claude Desktop and
 * Claude.ai share the custom-connector prefill (a button, not a snippet); Claude.ai is
 * public-only, which is why it never appears in the local (bridge) set.
 *
 * @return array<string, array<string, mixed>>
 */
function novamira_build_oauth_native_configs(string $mcp_url, string $mcp_name): array
{
    $tq = static fn(string $v): string => '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $v) . '"';
    $connector = novamira_build_connector_install_link(
        $mcp_url,
        novamira_build_connector_display_name(get_bloginfo('name')),
    );
    $deeplink =
        'cursor://anysphere.cursor-deeplink/mcp/install?name='
        . $mcp_name
        . '&config='
        . base64_encode((string) json_encode(['url' => $mcp_url]));

    $connector_entry = static fn(string $hint): array => [
        'kind' => 'connector',
        'code' => '',
        'connector' => $connector,
        'hint' => $hint,
        'paths' => [],
        'isShell' => false,
    ];

    return [
        'claude-code' => [
            'kind' => 'code',
            'code' => 'claude mcp add ' . $mcp_name . ' --transport http ' . $mcp_url,
            'hint' => __('Run in your terminal, then sign in when your browser opens.', domain: 'novamira'),
            'paths' => [],
            'isShell' => true,
        ],
        // Claude Desktop adds remote servers from its own Connectors UI. The one-click button goes
        // through claude.ai (account level) and only reaches Desktop after a sync, so the in-app
        // walkthrough is the primary here rather than that button.
        'claude-desktop' => [
            'kind' => 'code',
            'code' => '',
            'hint' => '',
            'paths' => [],
            'isShell' => false,
            'steps' => novamira_oauth_connector_steps('Claude Desktop', $mcp_name, $mcp_url),
        ],
        'claude-ai' => array_merge(
            $connector_entry(__(
                'Add it as a custom connector on claude.ai, then sign in. Works in the browser and in Claude Desktop.',
                domain: 'novamira',
            )),
            ['steps' => novamira_oauth_connector_steps('claude.ai', $mcp_name, $mcp_url)],
        ),
        'codex' => novamira_oauth_code_entry(
            "[mcp_servers.{$mcp_name}]\nurl = " . $tq($mcp_url),
            sprintf(
                /* translators: 1: config.toml file name, 2: codex mcp login command, both in <code> tags */
                __('Add to %1$s. Then sign in with %2$s.', domain: 'novamira'),
                '<code>config.toml</code>',
                '<code>codex mcp login</code>',
            ),
            ['macOS / Linux' => '~/.codex/config.toml', 'Windows' => '%USERPROFILE%\\.codex\\config.toml'],
        ),
        'cursor' => array_merge(
            novamira_oauth_code_entry(
                novamira_oauth_json('mcpServers', $mcp_name, ['url' => $mcp_url]),
                sprintf(__('Use the one-click button, or add to %s.', domain: 'novamira'), '<code>mcp.json</code>'),
                [
                    __('Global', domain: 'novamira') => '~/.cursor/mcp.json',
                    __('Project', domain: 'novamira') => '.cursor/mcp.json',
                ],
            ),
            ['deeplink' => $deeplink],
        ),
        'vscode' => novamira_oauth_code_entry(
            novamira_oauth_json('servers', $mcp_name, ['type' => 'http', 'url' => $mcp_url]),
            novamira_oauth_add_to('mcp.json'),
            [
                __('Workspace', domain: 'novamira') => '.vscode/mcp.json',
                __('User', domain: 'novamira') => __(
                    'Run: MCP: Open User Configuration (command palette)',
                    domain: 'novamira',
                ),
            ],
        ),
        'github-copilot' => novamira_oauth_code_entry(
            novamira_oauth_json('servers', $mcp_name, ['type' => 'http', 'url' => $mcp_url]),
            novamira_oauth_add_to('mcp.json'),
            [__('Project', domain: 'novamira') => '.github/copilot/mcp.json'],
        ),
        'gemini-cli' => novamira_oauth_code_entry(
            novamira_oauth_json('mcpServers', $mcp_name, ['httpUrl' => $mcp_url]),
            novamira_oauth_add_to('settings.json'),
            [
                __('Global', domain: 'novamira') => '~/.gemini/settings.json',
                __('Project', domain: 'novamira') => '.gemini/settings.json',
            ],
        ),
        'windsurf' => novamira_oauth_code_entry(
            novamira_oauth_json('mcpServers', $mcp_name, ['serverUrl' => $mcp_url]),
            novamira_oauth_add_to('mcp_config.json'),
            [
                'macOS / Linux' => '~/.codeium/windsurf/mcp_config.json',
                'Windows' => '%USERPROFILE%\\.codeium\\windsurf\\mcp_config.json',
            ],
        ),
    ];
}

/**
 * mcp-remote bridge configs for every client except the browser-only Claude.ai. Used for the
 * whole list on local sites and for the unverified tail on public sites. File paths mirror
 * novamira_build_configs()'s locations, kept here so the OAuth flow stays isolated from the
 * proven app-password renderer.
 *
 * @param array<string, string> $env
 * @return array<string, array<string, mixed>>
 */
function novamira_build_oauth_bridge_configs(string $mcp_url, string $mcp_name, array $env): array
{
    $server = novamira_oauth_bridge_server($mcp_url, $env);

    return array_merge(
        novamira_build_oauth_bridge_special($mcp_url, $mcp_name, $env, $server),
        novamira_build_oauth_bridge_standard(
            novamira_oauth_json('mcpServers', $mcp_name, $server),
            novamira_oauth_json('servers', $mcp_name, $server),
        ),
    );
}

/**
 * Bridge entries whose format is unique to the client (shell command, TOML, or a bespoke JSON
 * envelope) rather than the shared mcpServers/servers payload.
 *
 * @param array<string, string> $env
 * @param array<string, mixed>  $server
 * @return array<string, array<string, mixed>>
 */
function novamira_build_oauth_bridge_special(string $mcp_url, string $mcp_name, array $env, array $server): array
{
    $opts = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES;

    $zed_json = (string) json_encode([
        'context_servers' => [$mcp_name => array_merge(['source' => 'custom', 'enabled' => true], $server)],
    ], $opts);

    $opencode_server = ['type' => 'local', 'command' => ['npx', '-y', 'mcp-remote', $mcp_url]];
    if ($env !== []) {
        $opencode_server['environment'] = $env;
    }
    $opencode_json = (string) json_encode(['mcp' => [$mcp_name => $opencode_server]], $opts);

    return [
        'claude-code' => [
            'kind' => 'code',
            'code' => novamira_oauth_bridge_claude_code($mcp_name, $mcp_url, $env),
            'hint' => __('Run in your terminal, then sign in when your browser opens.', domain: 'novamira'),
            'paths' => [],
            'isShell' => true,
        ],
        'codex' => novamira_oauth_code_entry(
            novamira_oauth_bridge_codex($mcp_name, $mcp_url, $env),
            novamira_oauth_add_to('config.toml'),
            ['macOS / Linux' => '~/.codex/config.toml', 'Windows' => '%USERPROFILE%\\.codex\\config.toml'],
        ),
        'zed' => novamira_oauth_code_entry($zed_json, novamira_oauth_add_to('settings.json'), [
            'macOS / Linux' => '~/.config/zed/settings.json',
        ]),
        'opencode' => novamira_oauth_code_entry($opencode_json, novamira_oauth_add_to('opencode.json'), [
            __('Project', domain: 'novamira') => 'opencode.json',
            __('Global', domain: 'novamira') => '~/.config/opencode/opencode.json',
        ]),
    ];
}

/**
 * Bridge entries that reuse the shared mcpServers/servers JSON payloads. File paths mirror
 * novamira_build_configs()'s locations.
 *
 * @return array<string, array<string, mixed>>
 */
function novamira_build_oauth_bridge_standard(string $mcp_servers_json, string $servers_json): array
{
    return [
        'claude-desktop' => novamira_oauth_code_entry(
            $mcp_servers_json,
            novamira_oauth_add_to('claude_desktop_config.json'),
            [
                'macOS' => '~/Library/Application Support/Claude/claude_desktop_config.json',
                'Windows' => '%APPDATA%\\Claude\\claude_desktop_config.json',
            ],
        ),
        'antigravity' => novamira_oauth_code_entry($mcp_servers_json, novamira_oauth_add_to('mcp_config.json'), [
            'macOS / Linux' => '~/.gemini/antigravity/mcp_config.json',
            'Windows' => '%USERPROFILE%\\.gemini\\antigravity\\mcp_config.json',
        ]),
        'cursor' => novamira_oauth_code_entry($mcp_servers_json, novamira_oauth_add_to('mcp.json'), [
            __('Global', domain: 'novamira') => '~/.cursor/mcp.json',
            __('Project', domain: 'novamira') => '.cursor/mcp.json',
        ]),
        'vscode' => novamira_oauth_code_entry($servers_json, novamira_oauth_add_to('mcp.json'), [
            __('Workspace', domain: 'novamira') => '.vscode/mcp.json',
            __('User', domain: 'novamira') => __(
                'Run: MCP: Open User Configuration (command palette)',
                domain: 'novamira',
            ),
        ]),
        'github-copilot' => novamira_oauth_code_entry($servers_json, novamira_oauth_add_to('mcp.json'), [
            __('Project', domain: 'novamira') => '.github/copilot/mcp.json',
        ]),
        'windsurf' => novamira_oauth_code_entry($mcp_servers_json, novamira_oauth_add_to('mcp_config.json'), [
            'macOS / Linux' => '~/.codeium/windsurf/mcp_config.json',
            'Windows' => '%USERPROFILE%\\.codeium\\windsurf\\mcp_config.json',
        ]),
        'cline' => novamira_oauth_code_entry($mcp_servers_json, novamira_oauth_add_to('cline_mcp_settings.json'), [
            __('Via UI', domain: 'novamira') => __(
                'Cline sidebar → MCP Servers → Configure MCP Servers',
                domain: 'novamira',
            ),
        ]),
        'gemini-cli' => novamira_oauth_code_entry($mcp_servers_json, novamira_oauth_add_to('settings.json'), [
            __('Global', domain: 'novamira') => '~/.gemini/settings.json',
            __('Project', domain: 'novamira') => '.gemini/settings.json',
        ]),
        'roo-code' => novamira_oauth_code_entry($mcp_servers_json, novamira_oauth_add_to('mcp.json'), [
            __('Project', domain: 'novamira') => '.roo/mcp.json',
            __('Via UI', domain: 'novamira') => __(
                'Roo Code sidebar → MCP Servers → Configure MCP Servers',
                domain: 'novamira',
            ),
        ]),
        'amazon-q' => novamira_oauth_code_entry($mcp_servers_json, novamira_oauth_add_to('mcp.json'), [
            __('Global', domain: 'novamira') => '~/.aws/amazonq/mcp.json',
            __('Project', domain: 'novamira') => '.amazonq/mcp.json',
        ]),
        'kilo-code' => novamira_oauth_code_entry($mcp_servers_json, novamira_oauth_add_to('mcp.json'), [
            __('Project', domain: 'novamira') => '.kilocode/mcp.json',
            __('Via UI', domain: 'novamira') => __(
                'Kilo Code sidebar → MCP Servers → Configure MCP Servers',
                domain: 'novamira',
            ),
        ]),
    ];
}
