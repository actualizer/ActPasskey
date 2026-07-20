<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\WebAuthn\Ceremony;

use Actualize\Passkey\WebAuthn\Ceremony\CeremonyFactory;
use Actualize\Passkey\WebAuthn\Credential\Realm;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Webauthn\CeremonyStep\CeremonyStepManager;

final class CeremonyFactoryTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testBuildsBothManagers(): void
    {
        $sut = $this->getContainer()->get(CeremonyFactory::class);
        $ctx = Context::createDefaultContext();

        self::assertInstanceOf(CeremonyStepManager::class, $sut->creation(Realm::Customer, $ctx));
        self::assertInstanceOf(CeremonyStepManager::class, $sut->request(Realm::Customer, $ctx));
    }
}
