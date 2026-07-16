<?php declare(strict_types=1);
namespace Actualize\Passkey\Tests\Unit\WebAuthn\Credential;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
final class RealmTest extends TestCase {
    public function testStableStringValues(): void {
        self::assertSame('admin', Realm::Admin->value);
        self::assertSame('customer', Realm::Customer->value);
    }
    public function testFromString(): void {
        self::assertSame(Realm::Admin, Realm::from('admin'));
    }
}
