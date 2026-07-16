<?php declare(strict_types=1);
namespace Actualize\Passkey\Tests\Integration\Entity;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\Test\TestCaseBase\IntegrationTestBehaviour;
use Shopware\Core\Framework\Uuid\Uuid;
use PHPUnit\Framework\TestCase;
final class PasskeyCredentialCrudTest extends TestCase {
    use IntegrationTestBehaviour;
    public function testInsertAndRead(): void {
        /** @var EntityRepository $repo */
        $repo = $this->getContainer()->get('act_passkey_credential.repository');
        $ctx = Context::createDefaultContext();
        $repo->create([[
            'id' => Uuid::randomHex(), 'realm' => 'admin',
            'credentialId' => Uuid::randomBytes(), 'publicKey' => 'cose-bytes',
            'signCount' => 0, 'userHandle' => Uuid::randomBytes(),
            'aaguid' => Uuid::randomHex(), 'transports' => ['internal'], 'name' => 'Test Key',
        ]], $ctx);
        self::assertGreaterThanOrEqual(1, $repo->search(new Criteria(), $ctx)->getTotal());
    }
    public function testCredentialIdIsUnique(): void {
        /** @var EntityRepository $repo */
        $repo = $this->getContainer()->get('act_passkey_credential.repository');
        $ctx = Context::createDefaultContext();
        $cred = Uuid::randomBytes();
        $mk = fn() => [ 'id'=>Uuid::randomHex(),'realm'=>'admin','credentialId'=>$cred,'publicKey'=>'k','signCount'=>0,'userHandle'=>Uuid::randomBytes(),'aaguid'=>Uuid::randomHex(),'transports'=>['internal'],'name'=>'n' ];
        $repo->create([$mk()], $ctx);
        $this->expectException(\Throwable::class);
        $repo->create([$mk()], $ctx);
    }
}
