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

    /**
     * A public suffix such as co.uk gives an rp id every browser rejects, so every
     * registration would fail. There is no PSL check; the help text has to say it.
     */
    public function testBroadenParentDomainHelpTextWarnsAgainstPublicSuffixes(): void
    {
        $configurationService = static::getContainer()->get(ConfigurationService::class);
        static::assertInstanceOf(ConfigurationService::class, $configurationService);

        $cards = $configurationService->getConfiguration('ActPasskey.config', Context::createDefaultContext());

        $helpText = null;
        foreach ($cards as $card) {
            foreach ($card['elements'] ?? [] as $element) {
                if ($element['name'] === 'ActPasskey.config.broadenParentDomain') {
                    $helpText = $element['config']['helpText'] ?? null;
                }
            }
        }

        static::assertIsArray($helpText);
        static::assertStringContainsString(
            'Only enter a domain you own, never a public suffix such as co.uk or github.io',
            (string) ($helpText['en-GB'] ?? '')
        );
        static::assertStringContainsString(
            'Nur eine eigene Domain eintragen, niemals eine öffentliche Endung wie co.uk oder github.io',
            (string) ($helpText['de-DE'] ?? '')
        );
    }
}
