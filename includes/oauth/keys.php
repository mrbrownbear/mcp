<?php

// SPDX-FileCopyrightText: 2026 Ovation S.r.l. <dev@novamira.ai>
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace Novamira\OAuth\Keys;

use League\OAuth2\Server\CryptKey;

if (!defined('ABSPATH')) {
    exit();
}

const PRIVATE_KEY_OPTION = 'novamira_oauth_private_key';

const ENCRYPTION_KEY_OPTION = 'novamira_oauth_encryption_key';

/**
 * Returns the RSA private key (for signing), its derived public key (for verification),
 * and the symmetric encryption key. Generates and persists the secrets on first call.
 *
 * Only the private key and the encryption key are stored; the public key is derived from
 * the private key on read, so the signer and verifier can never drift out of sync (there
 * is no separate public-key option that a concurrent write could leave mismatched). Both
 * secrets are written with add_option, which does not overwrite an existing value, so two
 * concurrent first-use requests converge on a single persisted secret instead of racing
 * last-write-wins.
 *
 * @return array{private: CryptKey, public: CryptKey, encryption: string}
 */
function get(): array
{
    $private = (string) get_option(PRIVATE_KEY_OPTION, default_value: '');
    if ($private === '') {
        add_option(PRIVATE_KEY_OPTION, generate_private_key(), autoload: false);
        $private = (string) get_option(PRIVATE_KEY_OPTION, default_value: '');
    }
    if ($private === '') {
        throw new \RuntimeException('failed to persist OAuth private key');
    }

    $encryption = (string) get_option(ENCRYPTION_KEY_OPTION, default_value: '');
    if ($encryption === '') {
        add_option(ENCRYPTION_KEY_OPTION, base64_encode(random_bytes(32)), autoload: false);
        $encryption = (string) get_option(ENCRYPTION_KEY_OPTION, default_value: '');
    }
    if ($encryption === '') {
        throw new \RuntimeException('failed to persist OAuth encryption key');
    }

    return [
        'private' => new CryptKey($private, passPhrase: null, keyPermissionsCheck: false),
        'public' => new CryptKey(derive_public_key($private), passPhrase: null, keyPermissionsCheck: false),
        'encryption' => $encryption,
    ];
}

function generate_private_key(): string
{
    $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if ($res === false) {
        throw new \RuntimeException('openssl_pkey_new failed');
    }
    $private = '';
    openssl_pkey_export($res, $private);
    return $private;
}

function derive_public_key(string $private_pem): string
{
    $key = openssl_pkey_get_private($private_pem);
    if ($key === false) {
        throw new \RuntimeException('openssl_pkey_get_private failed');
    }
    $details = openssl_pkey_get_details($key);
    if ($details === false) {
        throw new \RuntimeException('openssl_pkey_get_details failed');
    }
    // @mago-expect analysis:possibly-undefined-string-array-index
    return (string) $details['key'];
}
