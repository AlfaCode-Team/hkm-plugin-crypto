<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Crypto;

use AlfacodeTeam\PhpServicePlatform\Kernel\Exceptions\KernelException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Crypto\Infrastructure\AesEncrypter;

/**
 * Regression cover for C-01 and C-02.
 */
#[CoversClass(AesEncrypter::class)]
final class AesEncrypterSecurityTest extends TestCase
{
    private const KEY = '0123456789abcdef0123456789abcdef';

    public function test_scalars_and_arrays_round_trip(): void
    {
        $e = new AesEncrypter([self::KEY]);

        self::assertSame('hello', $e->decrypt($e->encrypt('hello')));
        self::assertSame(['a' => 1, 'b' => [2, 3]], $e->decrypt($e->encrypt(['a' => 1, 'b' => [2, 3]])));
    }

    public function test_decrypt_does_not_instantiate_objects_from_the_payload(): void
    {
        // C-02: decrypt() consumes attacker-reachable ciphertext (cookies,
        // sessions). Without allowed_classes:false a payload could instantiate
        // arbitrary classes and fire __wakeup/__destruct — object injection.
        $e = new AesEncrypter([self::KEY]);

        $restored = $e->decrypt($e->encrypt(new \ArrayObject(['x' => 1])));

        self::assertInstanceOf(\__PHP_Incomplete_Class::class, $restored);
        self::assertNotInstanceOf(\ArrayObject::class, $restored);
    }

    public function test_tampered_payload_is_rejected(): void
    {
        $e = new AesEncrypter([self::KEY]);
        $payload = $e->encrypt('secret');

        $this->expectException(KernelException::class);
        $e->decrypt(strrev($payload));
    }

    public function test_a_different_key_cannot_decrypt(): void
    {
        $a = new AesEncrypter([self::KEY]);
        $b = new AesEncrypter(['fedcba9876543210fedcba9876543210']);

        $this->expectException(KernelException::class);
        $b->decrypt($a->encrypt('secret'));
    }
}
