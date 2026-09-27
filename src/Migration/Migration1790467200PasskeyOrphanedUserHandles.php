<?php declare(strict_types=1);

namespace Actualize\Passkey\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\Framework\Migration\MigrationStep;

class Migration1790467200PasskeyOrphanedUserHandles extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1790467200;
    }

    public function update(Connection $connection): void
    {
        // Handles of accounts deleted before the cleanup subscriber existed. UNHEX()
        // compares against the primary key, so the lookup uses its index and a handle
        // whose account exists is never removed; a malformed account id matches no
        // account and counts as orphaned. Other realms are left alone.
        $connection->executeStatement(<<<'SQL'
DELETE h FROM `act_passkey_user_handle` h
WHERE (h.`realm` = 'admin'
        AND NOT EXISTS (SELECT 1 FROM `user` u WHERE u.`id` = UNHEX(h.`account_id`)))
   OR (h.`realm` = 'customer'
        AND NOT EXISTS (SELECT 1 FROM `customer` c WHERE c.`id` = UNHEX(h.`account_id`)))
SQL);
    }
}
