<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\System\SystemConfig\Service\ConfigurationService;
use Shopware\Core\System\SystemConfig\SystemConfigService;

/**
 * @internal
 */
final class ConfigXmlTest extends TestCase
{
    use IntegrationTestBehaviour;

    public function testBroadenParentDomainDefaultsToUnset(): void
    {
        $config = static::getContainer()->get(SystemConfigService::class);
        static::assertInstanceOf(SystemConfigService::class, $config);

        // config.xml defaults are NOT written to system_config on install, so an
        // untouched key reads as null and the code must treat that as "no broadening".
        $value = $config->get('ActPasskey.config.broadenParentDomain');

        static::assertTrue($value === null || $value === '');
    }

    public function testConfigXmlDeclaresBroadenParentDomainField(): void
    {
        $configurationService = static::getContainer()->get(ConfigurationService::class);
        static::assertInstanceOf(ConfigurationService::class, $configurationService);

        // Reads src/Resources/config/config.xml through Shopware's own bundle config
        // reader, the same path the admin config screen uses to build its form. Throws
        // BundleConfigNotFoundException while the file does not exist yet.
        $cards = $configurationService->getConfiguration('ActPasskey.config', Context::createDefaultContext());

        $fieldNames = [];
        foreach ($cards as $card) {
            foreach ($card['elements'] ?? [] as $element) {
                $fieldNames[] = $element['name'];
            }
        }

        static::assertContains('ActPasskey.config.broadenParentDomain', $fieldNames);
    }
}
