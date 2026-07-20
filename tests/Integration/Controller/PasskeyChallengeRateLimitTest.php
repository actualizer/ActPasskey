<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Controller;

use Actualize\Passkey\Controller\Admin\PasskeyAdminChallengeController;
use Actualize\Passkey\WebAuthn\Ceremony\AuthenticationCeremony;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\RateLimiter\RateLimiter;
use Shopware\Core\Framework\RateLimiter\RateLimiterFactory;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\System\SystemConfig\SystemConfigService;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;

/**
 * Proves the unauthenticated challenge endpoint actually consults its limiter and
 * stops handing out challenges once the bucket is spent.
 *
 * APP_ENV=test wraps every container factory in NoLimiter, and in dev
 * `cache.rate_limiter` resolves to the array adapter (one request per counter) —
 * so neither environment can show this over HTTP. The test therefore re-registers
 * a real factory backed by process-local storage, over the plugin's OWN shipped
 * config: if the bucket's limit or policy regresses, this goes red.
 *
 * @internal
 */
final class PasskeyChallengeRateLimitTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testChallengeEndpointStopsServingOnceTheBucketIsSpent(): void
    {
        $limiterConfig = $this->shippedChallengeBucketConfig();
        $limit = $limiterConfig['limit'];

        $rateLimiter = new RateLimiter();
        $rateLimiter->registerLimiterFactory('act_passkey_challenge', new RateLimiterFactory(
            $limiterConfig,
            new InMemoryStorage(),
            static::getContainer()->get(SystemConfigService::class),
            static::getContainer()->get(ClockInterface::class),
        ));

        $ceremony = static::getContainer()->get(AuthenticationCeremony::class);
        static::assertInstanceOf(AuthenticationCeremony::class, $ceremony);
        $controller = new PasskeyAdminChallengeController($ceremony, $rateLimiter);

        $request = new Request();
        $request->server->set('REMOTE_ADDR', '203.0.113.7');
        $context = Context::createCLIContext();

        for ($i = 1; $i <= $limit; ++$i) {
            $controller->loginChallenge($request, $context);
        }

        $this->expectException(TooManyRequestsHttpException::class);
        $controller->loginChallenge($request, $context);
    }

    /**
     * @return array{id: string, enabled: bool, policy: string, limit: int, interval: string}
     */
    private function shippedChallengeBucketConfig(): array
    {
        $config = static::getContainer()->getParameter('shopware.api.rate_limiter');
        static::assertIsArray($config);
        static::assertArrayHasKey('act_passkey_challenge', $config);

        $bucket = $config['act_passkey_challenge'];
        static::assertIsArray($bucket);
        static::assertSame('fixed_window', $bucket['policy']);
        static::assertIsInt($bucket['limit']);
        static::assertIsString($bucket['interval']);

        return [
            'id' => 'act_passkey_challenge',
            'enabled' => true,
            'policy' => 'fixed_window',
            'limit' => $bucket['limit'],
            'interval' => $bucket['interval'],
        ];
    }
}
