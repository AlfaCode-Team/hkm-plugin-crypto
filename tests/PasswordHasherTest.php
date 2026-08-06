<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Crypto;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Crypto\Infrastructure\PasswordHasher;

#[CoversClass(PasswordHasher::class)]
final class PasswordHasherTest extends TestCase
{
    public function test_make_then_check_succeeds(): void
    {
        $hasher = new PasswordHasher();
        $hash = $hasher->make('s3cret');

        $this->assertNotSame('s3cret', $hash);
        $this->assertTrue($hasher->check('s3cret', $hash));
    }

    public function test_check_fails_for_wrong_password(): void
    {
        $hasher = new PasswordHasher();

        $this->assertFalse($hasher->check('wrong', $hasher->make('s3cret')));
    }

    public function test_check_fails_for_empty_hash(): void
    {
        $this->assertFalse((new PasswordHasher())->check('x', ''));
    }

    public function test_needs_rehash_when_cost_increases(): void
    {
        $low = new PasswordHasher(cost: 4);
        $hash = $low->make('s3cret');
        $high = new PasswordHasher(cost: 12);

        $this->assertTrue($high->needsRehash($hash));
        $this->assertFalse($low->needsRehash($hash));
    }

    // --- The 72-byte bcrypt limit (C-03) --------------------------------------

    /**
     * The core defect. bcrypt discards everything past 72 bytes, so two
     * passphrases sharing a 72-byte prefix used to authenticate each other —
     * a 100-character passphrase was worth only its first 72 characters.
     */
    public function test_long_passwords_are_not_truncated_at_72_bytes(): void
    {
        $hasher = new PasswordHasher(cost: 4);

        $password = str_repeat('a', 72) . 'CORRECT-tail';
        $attacker = str_repeat('a', 72) . 'WRONG-tail';

        $hash = $hasher->make($password);

        $this->assertTrue($hasher->check($password, $hash));
        $this->assertFalse(
            $hasher->check($attacker, $hash),
            'A password sharing only the first 72 bytes must not authenticate.',
        );
    }

    /**
     * bcrypt also stops at the first NUL byte, so "secret\0<anything>" collapsed
     * to "secret".
     */
    public function test_a_nul_byte_does_not_truncate_the_password(): void
    {
        $hasher = new PasswordHasher(cost: 4);
        $hash   = $hasher->make("secret\0tail");

        $this->assertTrue($hasher->check("secret\0tail", $hash));
        $this->assertFalse($hasher->check('secret', $hash));
        $this->assertFalse($hasher->check("secret\0other", $hash));
    }

    /**
     * Pre-hashing must not disturb ordinary passwords: their stored hash has to
     * stay byte-compatible with what earlier releases wrote, or every existing
     * user is locked out on deploy.
     */
    public function test_short_passwords_still_verify_against_a_pre_existing_hash(): void
    {
        $legacy = password_hash('s3cret', PASSWORD_BCRYPT, ['cost' => 4]);

        $this->assertTrue((new PasswordHasher(cost: 4))->check('s3cret', $legacy));
    }

    /**
     * Long-password hashes written before this change stored the truncated raw
     * value. They must keep working — the plaintext is gone, so they cannot be
     * repaired, only accepted until the user next sets a password.
     */
    public function test_a_legacy_truncated_hash_still_authenticates(): void
    {
        $password = str_repeat('a', 72) . 'tail';
        $legacy   = password_hash($password, PASSWORD_BCRYPT, ['cost' => 4]);

        $this->assertTrue((new PasswordHasher(cost: 4))->check($password, $legacy));
    }

    /** The stored hash stays 60 chars — the User plugin's column is CHAR(60). */
    public function test_hash_output_stays_within_the_bcrypt_column_width(): void
    {
        $hasher = new PasswordHasher(cost: 4);

        $this->assertSame(60, strlen($hasher->make('short')));
        $this->assertSame(60, strlen($hasher->make(str_repeat('x', 200))));
    }

    // --- Pepper ---------------------------------------------------------------

    public function test_pepper_changes_the_hash_of_a_long_password(): void
    {
        $password = str_repeat('a', 100);

        $peppered = new PasswordHasher(cost: 4, pepper: 'server-side-secret');
        $plain    = new PasswordHasher(cost: 4);

        // A hash made with the pepper must not verify without it. Otherwise the
        // pepper contributes nothing and a stolen table is still attackable.
        $this->assertFalse($plain->check($password, $peppered->make($password)));
        $this->assertTrue($peppered->check($password, $peppered->make($password)));
    }

    /**
     * The pepper is scoped to the pre-hash path. Applying it to every password
     * would change every stored hash and lock out every existing user, so short
     * passwords deliberately remain unpeppered.
     */
    public function test_pepper_does_not_alter_short_password_compatibility(): void
    {
        $legacy = password_hash('s3cret', PASSWORD_BCRYPT, ['cost' => 4]);

        $this->assertTrue((new PasswordHasher(cost: 4, pepper: 'secret'))->check('s3cret', $legacy));
    }

    // --- Argon2id -------------------------------------------------------------

    /**
     * Argon2id has no length limit and no NUL problem, so it must receive the
     * password untouched — pre-hashing it would cap the input entropy for no
     * reason and break compatibility with hashes made elsewhere.
     */
    public function test_argon2id_hashes_long_passwords_without_pre_hashing(): void
    {
        if (!defined('PASSWORD_ARGON2ID')) {
            $this->markTestSkipped('Argon2id is not compiled into this PHP build.');
        }

        $hasher   = new PasswordHasher(algo: PASSWORD_ARGON2ID);
        $password = str_repeat('a', 72) . 'tail';

        $hash = $hasher->make($password);

        $this->assertTrue($hasher->check($password, $hash));
        $this->assertFalse($hasher->check(str_repeat('a', 72), $hash));
        $this->assertTrue(
            password_verify($password, $hash),
            'Argon2id output must stay interoperable with a plain password_verify().',
        );
    }
}
