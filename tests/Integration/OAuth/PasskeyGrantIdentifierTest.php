<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\OAuth;

use Actualize\Passkey\OAuth\PasskeyGrant;
use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;

/**
 * AuthenticationCeremony is `final`, so it cannot be `createMock`'d — this is
 * an integration test pulling the real ceremony from the container; only the
 * (interface) refresh-token repository is mocked.
 */
final class PasskeyGrantIdentifierTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testIdentifierIsPasskey(): void
    {
        $ceremony = $this->getContainer()->get(AuthenticationCeremony::class);
        $grant = new PasskeyGrant($this->createMock(RefreshTokenRepositoryInterface::class), $ceremony, new NullLogger());

        self::assertSame('passkey', $grant->getIdentifier());
    }
}
