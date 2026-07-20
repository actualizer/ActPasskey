<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Controller;

use Actualize\Passkey\Controller\Store\PasskeyStoreApiController;
use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use Actualize\Passkey\WebAuthn\Customer\CustomerPasskeyLoginService;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Shopware\Core\Framework\RateLimiter\RateLimiter;
use Shopware\Core\Framework\RateLimiter\RateLimiterFactory;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\System\SalesChannel\Context\SalesChannelContextFactory;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Core\System\SystemConfig\SystemConfigService;
use Shopware\Core\Test\TestDefaults;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;

/**
 * Pins that failed customer logins accumulate against the bucket and eventually
 * get refused. The reset() on the success path must never run unconditionally:
 * that would empty the bucket on every call and leave the throttle inert, which
 * is worse than having none — this test is what catches that regression.
 *
 * See PasskeyChallengeRateLimitTest for why the limiter is built by hand rather
 * than taken from the container.
 *
 * @internal
 */
final class PasskeyLoginRateLimitTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testFailedLoginsAccumulateUntilTheBucketRefuses(): void
    {
        $burst = $this->firstBurstLimit();
        $controller = $this->buildController();

        $request = new Request();
        $request->server->set('REMOTE_ADDR', '203.0.113.9');
        $context = $this->createStorefrontContext();

        // An empty body fails after the throttle has already counted the attempt.
        for ($i = 1; $i <= $burst; ++$i) {
            try {
                $controller->login($request, new RequestDataBag([]), $context);
                self::fail('a passkey login without a body must not succeed');
            } catch (UnauthorizedHttpException) {
                // expected: the attempt was counted, then rejected
            }
        }

        $this->expectException(TooManyRequestsHttpException::class);
        $controller->login($request, new RequestDataBag([]), $context);
    }

    public function testASeparateClientIpKeepsItsOwnBudget(): void
    {
        $burst = $this->firstBurstLimit();
        $controller = $this->buildController();
        $context = $this->createStorefrontContext();

        $spent = new Request();
        $spent->server->set('REMOTE_ADDR', '203.0.113.10');
        for ($i = 1; $i <= $burst; ++$i) {
            try {
                $controller->login($spent, new RequestDataBag([]), $context);
            } catch (UnauthorizedHttpException) {
                // expected
            }
        }

        $fresh = new Request();
        $fresh->server->set('REMOTE_ADDR', '198.51.100.4');
        $this->expectException(UnauthorizedHttpException::class);
        $controller->login($fresh, new RequestDataBag([]), $context);
    }

    private function buildController(): PasskeyStoreApiController
    {
        $config = static::getContainer()->getParameter('shopware.api.rate_limiter');
        static::assertIsArray($config);
        static::assertArrayHasKey('act_passkey_login', $config);

        $bucket = $config['act_passkey_login'];
        static::assertIsArray($bucket);
        static::assertSame('time_backoff', $bucket['policy']);

        $rateLimiter = new RateLimiter();
        $rateLimiter->registerLimiterFactory('act_passkey_login', new RateLimiterFactory(
            $bucket + ['id' => 'act_passkey_login'],
            new InMemoryStorage(),
            static::getContainer()->get(SystemConfigService::class),
            static::getContainer()->get(ClockInterface::class),
        ));

        $ceremony = static::getContainer()->get(AuthenticationCeremony::class);
        static::assertInstanceOf(AuthenticationCeremony::class, $ceremony);
        $loginService = static::getContainer()->get(CustomerPasskeyLoginService::class);
        static::assertInstanceOf(CustomerPasskeyLoginService::class, $loginService);

        return new PasskeyStoreApiController($ceremony, $loginService, $rateLimiter);
    }

    private function firstBurstLimit(): int
    {
        $config = static::getContainer()->getParameter('shopware.api.rate_limiter');
        static::assertIsArray($config);
        $limit = $config['act_passkey_login']['limits'][0]['limit'];
        static::assertIsInt($limit);

        return $limit;
    }

    private function createStorefrontContext(): SalesChannelContext
    {
        return static::getContainer()->get(SalesChannelContextFactory::class)
            ->create(Uuid::randomHex(), TestDefaults::SALES_CHANNEL);
    }
}
