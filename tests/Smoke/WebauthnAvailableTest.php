<?php declare(strict_types=1);
namespace Actualize\Passkey\Tests\Smoke;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
final class WebauthnAvailableTest extends TestCase
{
    use IntegrationTestBehaviour;
    public function testWebauthnLibraryIsAutoloadable(): void
    {
        self::assertTrue(class_exists(\Webauthn\PublicKeyCredential::class), 'web-auth/webauthn-lib must be autoloadable in the test kernel');
    }
}
