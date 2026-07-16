<?php declare(strict_types=1);

namespace Actualize\Passkey;

use Shopware\Core\Framework\Plugin;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class ActPasskey extends Plugin
{
    public function executeComposerCommands(): bool
    {
        return true;
    }

    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        // Plugin::build() does not read Resources/config/packages — only Framework,
        // Administration and Storefront call this. Needed for our rate_limiter keys.
        $this->buildDefaultConfig($container);
    }
}
