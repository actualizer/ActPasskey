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
}
