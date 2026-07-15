<?php declare(strict_types=1);

namespace Actualize\Passkey;

use Shopware\Core\Framework\Plugin;

class ActPasskey extends Plugin
{
    public function executeComposerCommands(): bool
    {
        return true;
    }
}
