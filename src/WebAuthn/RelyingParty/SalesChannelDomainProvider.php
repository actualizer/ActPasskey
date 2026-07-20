<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\RelyingParty;

use Shopware\Core\Defaults;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\System\SalesChannel\Aggregate\SalesChannelDomain\SalesChannelDomainCollection;

/**
 * The single source for "is this domain a real sales channel". Both the relying
 * party id and the origin allowlist derive from it, so the two cannot answer the
 * same question differently.
 */
final class SalesChannelDomainProvider
{
    /**
     * @param EntityRepository<SalesChannelDomainCollection> $domainRepository
     */
    public function __construct(private readonly EntityRepository $domainRepository)
    {
    }

    /** @return list<string> */
    public function hosts(Context $context): array
    {
        $hosts = [];
        foreach ($this->urls($context) as $url) {
            $host = parse_url($url, PHP_URL_HOST);
            if (is_string($host) && $host !== '') {
                $hosts[] = strtolower($host);
            }
        }

        return array_values(array_unique($hosts));
    }

    /** @return list<string> */
    public function origins(Context $context): array
    {
        $origins = [];
        foreach ($this->urls($context) as $url) {
            $parts = parse_url($url);
            if (!isset($parts['scheme'], $parts['host'])) {
                continue;
            }

            $origin = $parts['scheme'] . '://' . strtolower($parts['host']);
            if (isset($parts['port'])) {
                $origin .= ':' . $parts['port'];
            }

            $origins[] = $origin;
        }

        return array_values(array_unique($origins));
    }

    /**
     * Headless and product-comparison channels carry placeholder domains that must
     * never become a relying party id.
     *
     * @return list<string>
     */
    private function urls(Context $context): array
    {
        $criteria = (new Criteria())
            ->addFilter(new EqualsFilter('salesChannel.active', true))
            ->addFilter(new EqualsFilter('salesChannel.typeId', Defaults::SALES_CHANNEL_TYPE_STOREFRONT));

        $domains = $this->domainRepository->search($criteria, $context);

        $urls = [];
        foreach ($domains as $domain) {
            $url = $domain->getUrl();
            if ($url !== '') {
                $urls[] = $url;
            }
        }

        return $urls;
    }
}
