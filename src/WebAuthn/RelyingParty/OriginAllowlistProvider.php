<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\RelyingParty;

use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\System\SalesChannel\Aggregate\SalesChannelDomain\SalesChannelDomainCollection;

/**
 * Builds the WebAuthn trusted origin allowlist exclusively from configuration
 * (`APP_URL`) and the `sales_channel_domain` table. The request Host header
 * is NEVER consulted here - `origins()` only accepts a `Context`, so there is
 * no input path through which a hostile Host header could influence the
 * allowlist.
 */
final class OriginAllowlistProvider
{
    /**
     * @param EntityRepository<SalesChannelDomainCollection> $salesChannelDomainRepository
     */
    public function __construct(
        private readonly string $appUrl,
        private readonly EntityRepository $salesChannelDomainRepository,
    ) {
    }

    /** @return list<string> */
    public function origins(Context $context): array
    {
        $origins = [$this->toOrigin($this->appUrl)];

        $domains = $this->salesChannelDomainRepository->search(new Criteria(), $context);
        foreach ($domains as $domain) {
            $url = $domain->getUrl();
            if ($url !== '') {
                $origins[] = $this->toOrigin($url);
            }
        }

        return array_values(array_unique(array_filter($origins)));
    }

    private function toOrigin(string $url): string
    {
        $parts = parse_url($url);
        if (!isset($parts['scheme'], $parts['host'])) {
            return '';
        }

        $origin = $parts['scheme'] . '://' . $parts['host'];
        if (isset($parts['port'])) {
            $origin .= ':' . $parts['port'];
        }

        return $origin;
    }
}
