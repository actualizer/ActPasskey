<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Migration;

use Actualize\Passkey\Migration\Migration1790337600PasskeyCredentialIdLength;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Test\TestCaseBase\KernelTestBehaviour;

/**
 * WebAuthn credential ids may be up to 1023 bytes. The column must hold that
 * without truncation, keep its unique key, and the migration must be re-runnable.
 *
 * DDL commits implicitly, so this test deliberately runs without the
 * transaction wrapper of IntegrationTestBehaviour.
 *
 * @internal
 */
final class Migration1790337600PasskeyCredentialIdLengthTest extends TestCase
{
    use KernelTestBehaviour;

    public function testCredentialIdColumnHoldsTheWebAuthnMaximum(): void
    {
        $connection = $this->getContainer()->get(Connection::class);
        self::assertInstanceOf(Connection::class, $connection);

        $migration = new Migration1790337600PasskeyCredentialIdLength();
        $migration->update($connection);
        $migration->update($connection);

        $column = $connection->fetchAssociative(
            'SELECT `DATA_TYPE`, `CHARACTER_OCTET_LENGTH`, `IS_NULLABLE`
             FROM `information_schema`.`COLUMNS`
             WHERE `TABLE_SCHEMA` = DATABASE()
               AND `TABLE_NAME` = \'act_passkey_credential\'
               AND `COLUMN_NAME` = \'credential_id\''
        );
        self::assertIsArray($column);
        self::assertSame('varbinary', strtolower((string) $column['DATA_TYPE']));
        self::assertSame(1023, (int) $column['CHARACTER_OCTET_LENGTH']);
        self::assertSame('NO', $column['IS_NULLABLE']);

        $unique = $connection->fetchOne(
            'SELECT COUNT(*) FROM `information_schema`.`STATISTICS`
             WHERE `TABLE_SCHEMA` = DATABASE()
               AND `TABLE_NAME` = \'act_passkey_credential\'
               AND `INDEX_NAME` = \'uniq.act_passkey_credential.credential_id\'
               AND `NON_UNIQUE` = 0'
        );
        self::assertSame(1, (int) $unique);
    }
}
