<?php declare(strict_types=1);

namespace Actualize\Passkey\Tests\Unit\WebAuthn\RelyingParty;

use Actualize\Passkey\WebAuthn\RelyingParty\OriginAllowlistProvider;
use PHPUnit\Framework\TestCase;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityCollection;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\EntitySearchResult;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\System\SalesChannel\Aggregate\SalesChannelDomain\SalesChannelDomainEntity;

/**
 * Security-invariant test: `OriginAllowlistProvider::origins()` takes ONLY a
 * `Context`. There is no host/request parameter anywhere in its public API,
 * so a hostile `Host` header has no path into the allowlist - the allowlist
 * is entirely a function of the injected app-url string and whatever the
 * (mocked, here fully controlled) sales_channel_domain repository returns.
 */
final class OriginAllowlistHostInjectionTest extends TestCase
{
    public function testOriginsAcceptsOnlyContextNoHostInput(): void
    {
        $method = new \ReflectionMethod(OriginAllowlistProvider::class, 'origins');
        $parameters = $method->getParameters();

        self::assertCount(1, $parameters, 'origins() must not accept any argument besides Context');
        self::assertSame(Context::class, $parameters[0]->getType()?->getName());
    }

    public function testOnlyConfigDataDrivesAllowlist(): void
    {
        $repo = $this->createMock(EntityRepository::class);

        // Real (but bare, unpersisted) SalesChannelDomainEntity as the stub element:
        // EntityCollection enforces `instanceof Entity`, so a plain anonymous class
        // is rejected - this is the concrete manifestation of the "awkward under
        // 6.7.10" note in the task brief. No Host header or request object is
        // involved anywhere in this setup; the URL is a hard-coded literal.
        $entity = new SalesChannelDomainEntity();
        $entity->setUniqueIdentifier(Uuid::randomHex());
        $entity->setUrl('https://configured.example.com');

        $result = new EntitySearchResult(
            'sales_channel_domain',
            1,
            new EntityCollection([$entity]),
            null,
            new Criteria(),
            Context::createDefaultContext()
        );
        $repo->method('search')->willReturn($result);

        $sut = new OriginAllowlistProvider('https://app.example.com', $repo);
        $origins = $sut->origins(Context::createDefaultContext());

        self::assertContains('https://app.example.com', $origins);
        self::assertContains('https://configured.example.com', $origins);
        self::assertCount(2, $origins, 'only the two configured/DB-backed origins are present, nothing else');
    }
}
