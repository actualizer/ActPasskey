<?php declare(strict_types=1);

namespace Actualize\Passkey\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

class Migration1790467300PasskeyCloneWarning extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790467300;
    }

    public function update(Connection $connection): void
    {
        $exists = $connection->fetchOne(
            'SELECT 1 FROM `information_schema`.`COLUMNS`
             WHERE `TABLE_SCHEMA` = DATABASE()
               AND `TABLE_NAME` = \'act_passkey_credential\'
               AND `COLUMN_NAME` = \'clone_warning_at\''
        );
        if ($exists !== false) {
            return;
        }

        // When a login first showed a signature counter that did not go up.
        $connection->executeStatement(
            'ALTER TABLE `act_passkey_credential` ADD `clone_warning_at` DATETIME(3) NULL AFTER `last_used_at`'
        );
    }
}
