<?php declare(strict_types=1);
namespace Actualize\Passkey\Tests\Integration\Entity;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use PHPUnit\Framework\TestCase;
final class PasskeyUserHandleCrudTest extends TestCase {
    use IntegrationTestBehaviour;
    public function testInsertAndReadBack(): void {
        /** @var EntityRepository $repo */
        $repo = $this->getContainer()->get('act_passkey_user_handle.repository');
        $ctx = Context::createDefaultContext();
        $acc = Uuid::randomHex();
        $repo->create([[ 'id'=>Uuid::randomHex(),'realm'=>'admin','accountId'=>$acc,'userHandle'=>Uuid::randomBytes() ]], $ctx);
        $found = $repo->search(new Criteria(), $ctx);
        self::assertGreaterThanOrEqual(1, $found->getTotal());
    }
    public function testUserHandleUnique(): void {
        /** @var EntityRepository $repo */
        $repo = $this->getContainer()->get('act_passkey_user_handle.repository');
        $ctx = Context::createDefaultContext();
        $handle = Uuid::randomBytes();
        $repo->create([[ 'id'=>Uuid::randomHex(),'realm'=>'admin','accountId'=>Uuid::randomHex(),'userHandle'=>$handle ]], $ctx);
        $this->expectException(\Throwable::class);
        $repo->create([[ 'id'=>Uuid::randomHex(),'realm'=>'customer','accountId'=>Uuid::randomHex(),'userHandle'=>$handle ]], $ctx);
    }
}
