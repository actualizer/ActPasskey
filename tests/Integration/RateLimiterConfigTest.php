<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;

/**
 * @internal
 */
class RateLimiterConfigTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testPluginRegistersItsOwnRateLimiterBuckets(): void
    {
        $config = static::getContainer()->getParameter('shopware.api.rate_limiter');

        static::assertIsArray($config);
        static::assertArrayHasKey('act_passkey_register', $config);
        static::assertArrayHasKey('act_passkey_delete', $config);
        static::assertSame('time_backoff', $config['act_passkey_register']['policy']);
    }

    public function testChallengeBucketThrottlesPerWindowWithoutLockingOutTheIp(): void
    {
        $config = static::getContainer()->getParameter('shopware.api.rate_limiter');

        static::assertIsArray($config);
        static::assertArrayHasKey('act_passkey_challenge', $config);
        // fixed_window, not time_backoff: the key is the bare client IP, so an
        // escalating lockout would bar everyone behind the same NAT.
        static::assertSame('fixed_window', $config['act_passkey_challenge']['policy']);
        static::assertArrayNotHasKey('reset', $config['act_passkey_challenge']);
        static::assertSame(60, $config['act_passkey_challenge']['limit']);
    }

    public function testLoginBucketBacksOffOnRepeatedFailures(): void
    {
        $config = static::getContainer()->getParameter('shopware.api.rate_limiter');

        static::assertIsArray($config);
        static::assertArrayHasKey('act_passkey_login', $config);
        // time_backoff is safe here precisely because the callers reset() on a
        // successful login, so only failed attempts ever accumulate.
        static::assertSame('time_backoff', $config['act_passkey_login']['policy']);
        static::assertNotEmpty($config['act_passkey_login']['limits']);
    }
}
