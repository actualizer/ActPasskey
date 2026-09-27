<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Integration\Migration;

use Actualize\Passkey\Migration\Migration1790467300PasskeyCloneWarning;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Test\TestCaseBase\KernelTestBehaviour;

/**
 * DDL commits implicitly, so this test deliberately runs without the transaction
 * wrapper of IntegrationTestBehaviour.
 *
 * @internal
 */
final class Migration1790467300PasskeyCloneWarningTest extends TestCase
{
    use KernelTestBehaviour;

    public function testAddsANullableCloneWarningColumnAndIsReRunnable(): void
    {
        $connection = $this->getContainer()->get(Connection::class);
        self::assertInstanceOf(Connection::class, $connection);

        $migration = new Migration1790467300PasskeyCloneWarning();
        $migration->update($connection);
        $migration->update($connection);

        $column = $connection->fetchAssociative(
            'SELECT `DATA_TYPE`, `DATETIME_PRECISION`, `IS_NULLABLE`
             FROM `information_schema`.`COLUMNS`
             WHERE `TABLE_SCHEMA` = DATABASE()
               AND `TABLE_NAME` = \'act_passkey_credential\'
               AND `COLUMN_NAME` = \'clone_warning_at\''
        );
        self::assertIsArray($column);
        self::assertSame('datetime', strtolower((string) $column['DATA_TYPE']));
        self::assertSame(3, (int) $column['DATETIME_PRECISION']);
        self::assertSame('YES', $column['IS_NULLABLE']);
    }
}
