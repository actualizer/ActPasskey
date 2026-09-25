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
        // WebAuthn allows credential ids of up to 1023 bytes. At 255 a longer id
        // failed the insert (strict SQL mode) or was silently truncated and could
        // never log in again. MODIFY to the same definition is a no-op, so the
        // step is safe to re-run. 1023 bytes stays below the 3072-byte InnoDB
        // index limit, so the unique key is kept as is.
        $connection->executeStatement(
            'ALTER TABLE `act_passkey_credential` MODIFY `credential_id` VARBINARY(1023) NOT NULL'
        );
    }
}
