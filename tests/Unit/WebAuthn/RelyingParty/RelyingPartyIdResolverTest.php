<?php declare(strict_types=1);
namespace Actualize\Passkey\Tests\Unit\WebAuthn\RelyingParty;
use Actualize\Passkey\WebAuthn\RelyingParty\RelyingPartyIdResolver;
use Actualize\Passkey\WebAuthn\RelyingParty\UnsupportedHostException;
use PHPUnit\Framework\TestCase;
final class RelyingPartyIdResolverTest extends TestCase {
    public function testDefaultReturnsAppUrlHost(): void {
        $sut = new RelyingPartyIdResolver('https://sw66-pluginentwicklung.ddev.site', null);
        self::assertSame('sw66-pluginentwicklung.ddev.site', $sut->resolve('sw66-pluginentwicklung.ddev.site'));
    }
    public function testUncoveredHostRejected(): void {
        $sut = new RelyingPartyIdResolver('https://shop.example.com', null);
        $this->expectException(UnsupportedHostException::class);
        $sut->resolve('evil.attacker.test');
    }
    public function testConfiguredParentCoversSubdomain(): void {
        $sut = new RelyingPartyIdResolver('https://shop.example.com', 'example.com');
        self::assertSame('example.com', $sut->resolve('admin.example.com'));
    }
    public function testAppHostSubdomainCoveredByDefault(): void {
        $sut = new RelyingPartyIdResolver('https://example.com', null);
        self::assertSame('example.com', $sut->resolve('shop.example.com'));
    }
}
