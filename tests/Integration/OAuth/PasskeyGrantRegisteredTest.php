<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\OAuth;

use Actualize\Passkey\OAuth\PasskeyGrantSubscriber;
use League\OAuth2\Server\AuthorizationServer;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Symfony\Component\HttpKernel\KernelEvents;

final class PasskeyGrantRegisteredTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testPasskeyGrantIsEnabledOnAuthorizationServer(): void
    {
        $subscriber = $this->getContainer()->get(PasskeyGrantSubscriber::class);
        self::assertNotNull($subscriber);

        $subscriber->enablePasskeyGrant();

        $server = $this->getContainer()->get('shopware.api.authorization_server');
        self::assertInstanceOf(AuthorizationServer::class, $server);

        $ref = new \ReflectionObject($server);
        $prop = $ref->getProperty('enabledGrantTypes');
        $prop->setAccessible(true);
        /** @var array<string,mixed> $enabled */
        $enabled = $prop->getValue($server);

        self::assertArrayHasKey('passkey', $enabled, 'passkey grant must be enabled on the shared server');
    }

    public function testSubscribesToKernelRequest(): void
    {
        $events = PasskeyGrantSubscriber::getSubscribedEvents();

        self::assertArrayHasKey(KernelEvents::REQUEST, $events);
    }
}
