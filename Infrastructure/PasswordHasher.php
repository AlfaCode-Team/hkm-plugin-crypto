<?php

declare(strict_types=1);

namespace Plugins\Crypto\Infrastructure;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HashingPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\KernelException;

/**
 * Password hasher over PHP's native password_* functions.
 *
 * Defaults to bcrypt; pass algo 'argon2id' to use Argon2id where available.
 * check() is timing-safe via password_verify().
 *
 * THE 72-BYTE BCRYPT LIMIT
 * -----------------------
 * bcrypt hashes at most 72 bytes of input and DISCARDS the rest — silently. A
 * user with a 100-character passphrase was protected by only its first 72
 * bytes, and every passphrase sharing that prefix mapped to the same hash. It
 * also truncates at the first NUL byte, so a value containing one was reduced
 * to whatever preceded it. Neither failure was visible anywhere: registration
 * succeeded, login succeeded, and the extra entropy the user believed they had
 * simply did not exist. The longer and more carefully chosen the passphrase,
 * the more of it was thrown away.
 *
 * Inputs that bcrypt cannot represent faithfully are therefore PRE-HASHED to a
 * fixed 64-character digest before hashing (the standard bcrypt-sha construction):
 *
 *     base64(hmac-sha384(pepper, password))   // 64 chars, NUL-free, < 72
 *
 * SHA-384 is chosen so the base64 output lands on exactly 64 characters with no
 * padding and comfortably under the limit. The whole password contributes to
 * the digest, so all of its entropy reaches bcrypt.
 *
 * BACKWARD COMPATIBILITY
 * ----------------------
 * Pre-hashing applies ONLY to inputs that bcrypt would have mangled (>72 bytes,
 * or containing a NUL). Everything else — the overwhelming majority of real
 * passwords — is hashed exactly as before, so existing stored hashes keep
 * verifying unchanged and no migration is required. The stored hash also stays
 * exactly 60 characters, which matters: the User plugin's column is CHAR(60).
 *
 * For the long-password case, check() verifies against the pre-hashed form and
 * then falls back to the raw value, so hashes written before this change still
 * authenticate. Those legacy rows remain truncated until the user next sets a
 * password; there is no way to repair them without the plaintext.
 *
 * THE PEPPER
 * ----------
 * An optional secret mixed into the pre-hash as the HMAC key. It lives outside
 * the database (env / a secrets manager), so an attacker who exfiltrates the
 * user table alone cannot mount an offline guessing attack. It is NOT a
 * replacement for the per-hash salt bcrypt already applies.
 *
 * Two consequences worth stating plainly:
 *
 *  - The pepper only reaches passwords that get pre-hashed. Short passwords go
 *    to bcrypt verbatim, exactly as they always did. Peppering every password
 *    would change every hash and lock out every existing user, so it is scoped
 *    to the path that is changing anyway.
 *  - Changing or losing the pepper invalidates the long-password hashes that
 *    were made with it. Set it once, at deployment, and store it where you
 *    store APP_KEY.
 */
final class PasswordHasher implements HashingPort
{
    /**
     * bcrypt's hard input limit. Anything longer is silently discarded, so it
     * is the threshold at which pre-hashing becomes necessary.
     */
    private const BCRYPT_MAX_BYTES = 72;

    public function __construct(
        private readonly string $algo = PASSWORD_BCRYPT,
        private readonly int $cost = 12,
        /** Optional secret HMAC key for the pre-hash. Empty disables peppering. */
        private readonly string $pepper = '',
    ) {
    }

    public function make(string $value, array $options = []): string
    {
        $hash = password_hash($this->prepare($value), $this->algo, $this->options($options));

        if (!is_string($hash)) {
            throw new KernelException('Password hashing failed.', layer: 'crypto.hasher');
        }

        return $hash;
    }

    public function check(string $value, string $hashedValue): bool
    {
        if ($hashedValue === '') {
            return false;
        }

        $prepared = $this->prepare($value);

        if (password_verify($prepared, $hashedValue)) {
            return true;
        }

        // Legacy fallback: hashes written before pre-hashing existed stored the
        // truncated raw value. Only reachable when the input actually needed
        // preparing, so a normal password costs exactly one verify as before.
        if ($prepared !== $value && password_verify($value, $hashedValue)) {
            return true;
        }

        return false;
    }

    public function needsRehash(string $hashedValue, array $options = []): bool
    {
        return password_needs_rehash($hashedValue, $this->algo, $this->options($options));
    }

    /**
     * Reduce an input bcrypt cannot hash faithfully to a fixed-width digest.
     *
     * Returns the value unchanged when bcrypt handles it correctly, which keeps
     * every existing hash valid. Non-bcrypt algorithms (Argon2id) have no length
     * limit and no NUL problem, so they are left alone entirely.
     */
    private function prepare(string $value): string
    {
        if ($this->algo !== PASSWORD_BCRYPT) {
            return $value;
        }

        if (strlen($value) <= self::BCRYPT_MAX_BYTES && !str_contains($value, "\0")) {
            return $value;
        }

        // base64 of a 48-byte digest is exactly 64 chars, unpadded and NUL-free.
        return base64_encode(hash_hmac('sha384', $value, $this->pepper, binary: true));
    }

    /**
     * @param array<string,mixed> $options
     * @return array<string,int>
     */
    private function options(array $options): array
    {
        if ($this->algo === PASSWORD_BCRYPT) {
            return ['cost' => (int) ($options['cost'] ?? $this->cost)];
        }
        // Argon2 parameters fall back to PHP defaults unless overridden.
        return array_filter([
            'memory_cost' => isset($options['memory_cost']) ? (int) $options['memory_cost'] : null,
            'time_cost'   => isset($options['time_cost']) ? (int) $options['time_cost'] : null,
            'threads'     => isset($options['threads']) ? (int) $options['threads'] : null,
        ], static fn($v) => $v !== null);
    }
}
