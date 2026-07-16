<?php declare(strict_types=1);

namespace Actualize\Passkey\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

class Migration1752624100PasskeyUserHandle extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1752624100;
    }

    public function update(Connection $connection): void
    {
        $connection->executeStatement(<<<'SQL'
CREATE TABLE IF NOT EXISTS `act_passkey_user_handle` (
    `id`           BINARY(16)    NOT NULL,
    `realm`        VARCHAR(255)  NOT NULL,
    `account_id`   VARCHAR(64)   NOT NULL,
    `user_handle`  VARBINARY(64) NOT NULL,
    `created_at`   DATETIME(3)   NOT NULL,
    `updated_at`   DATETIME(3)   NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uniq.act_passkey_user_handle.realm_account` (`realm`, `account_id`),
    UNIQUE KEY `uniq.act_passkey_user_handle.user_handle` (`user_handle`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SQL);
    }
}
