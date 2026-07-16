<?php declare(strict_types=1);

namespace Actualize\Passkey\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

class Migration1752624200PasskeyLastUsedAt extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1752624200;
    }

    public function update(Connection $connection): void
    {
        $connection->executeStatement(
            'ALTER TABLE `act_passkey_credential` ADD `last_used_at` DATETIME(3) NULL AFTER `name`'
        );
    }
}
