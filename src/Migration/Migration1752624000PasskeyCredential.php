<?php declare(strict_types=1);

namespace Actualize\Passkey\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

class Migration1752624000PasskeyCredential extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1752624000;
    }

    public function update(Connection $connection): void
    {
        $connection->executeStatement(<<<'SQL'
CREATE TABLE IF NOT EXISTS `act_passkey_credential` (
    `id`             BINARY(16)     NOT NULL,
    `realm`          VARCHAR(255)   NOT NULL,
    `user_id`        BINARY(16)     NULL,
    `customer_id`    BINARY(16)     NULL,
    `credential_id`  VARBINARY(255) NOT NULL,
    `public_key`     BLOB           NOT NULL,
    `sign_count`     INT UNSIGNED   NOT NULL,
    `user_handle`    VARBINARY(64)  NOT NULL,
    `aaguid`         VARCHAR(255)   NULL,
    `transports`     JSON           NULL,
    `name`           VARCHAR(255)   NULL,
    `created_at`     DATETIME(3)    NOT NULL,
    `updated_at`     DATETIME(3)    NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uniq.act_passkey_credential.credential_id` (`credential_id`),
    KEY `idx.act_passkey_credential.user_id` (`user_id`),
    KEY `idx.act_passkey_credential.customer_id` (`customer_id`),
    CONSTRAINT `fk.act_passkey_credential.user_id`
        FOREIGN KEY (`user_id`)
        REFERENCES `user` (`id`)
        ON DELETE CASCADE,
    CONSTRAINT `fk.act_passkey_credential.customer_id`
        FOREIGN KEY (`customer_id`)
        REFERENCES `customer` (`id`)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SQL);
    }
}
