<?php declare(strict_types=1);

namespace Actualize\Passkey\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

class Migration1790337600PasskeyCredentialIdLength extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790337600;
    }

    public function update(Connection $connection): void
    {
        // WebAuthn credential ids may be up to 1023 bytes (still within the InnoDB
        // index limit for the unique key). Re-running MODIFY is a no-op.
        $connection->executeStatement(
            'ALTER TABLE `act_passkey_credential` MODIFY `credential_id` VARBINARY(1023) NOT NULL'
        );
    }
}
