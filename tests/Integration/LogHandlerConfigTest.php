<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration;

use Monolog\Handler\RotatingFileHandler;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;

/**
 * Shopware core's prod config only writes `error` and above (see the comment in
 * src/Resources/config/packages/monolog.yaml), so the plugin's own WARNING-level audit
 * and enrollment records would otherwise never reach a handler in production. This proves
 * the dedicated handler is actually wired up, not just declared in YAML.
 *
 * @internal
 */
class LogHandlerConfigTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testActPasskeyChannelHasItsOwnRotatingFileHandlerAtWarningLevel(): void
    {
        $handler = static::getContainer()->get('monolog.handler.act_passkey');

        static::assertInstanceOf(RotatingFileHandler::class, $handler);
        static::assertSame(Level::Warning, $handler->getLevel());
    }

    public function testTheHandlerIsAttachedToTheActPasskeyLogger(): void
    {
        $handler = static::getContainer()->get('monolog.handler.act_passkey');
        $logger = static::getContainer()->get('monolog.logger.act_passkey');

        static::assertInstanceOf(Logger::class, $logger);
        static::assertContains($handler, $logger->getHandlers());
    }
}
