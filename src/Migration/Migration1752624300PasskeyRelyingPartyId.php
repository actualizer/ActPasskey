<?php declare(strict_types=1);

namespace Actualize\Passkey\Migration;

use Doctrine\DBAL\Connection;
use Shopware\Core\DevOps\Environment\EnvironmentHelper;
use Shopware\Core\Framework\Migration\MigrationStep;

class Migration1752624300PasskeyRelyingPartyId extends MigrationStep
{
    public function getCreationTimestamp(): int
    {
        return 1752624300;
    }

    public function update(Connection $connection): void
    {
        $connection->executeStatement(
            'ALTER TABLE `act_passkey_credential` ADD `rp_id` VARCHAR(255) NULL AFTER `realm`'
        );

        // Existing rows can only ever have used the APP_URL host as their rp id.
        $appHost = parse_url((string) EnvironmentHelper::getVariable('APP_URL', ''), PHP_URL_HOST);
        if (!is_string($appHost) || $appHost === '') {
            return;
        }

        $connection->executeStatement(
            'UPDATE `act_passkey_credential` SET `rp_id` = :rpId WHERE `rp_id` IS NULL',
            ['rpId' => strtolower($appHost)]
        );
    }
}
