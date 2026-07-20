<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\RelyingParty;

use Actualize\Passkey\WebAuthn\Credential\Realm;
use Shopware\Core\Framework\Context;

/**
 * Builds the WebAuthn trusted origin allowlist from `APP_URL` and, for the customer
 * realm only, the active storefront domains. The request Host header is NEVER
 * consulted: `origins()` takes only a realm and a context.
 */
final class OriginAllowlistProvider
{
    public function __construct(
        private readonly string $appUrl,
        private readonly SalesChannelDomainProvider $domains,
    ) {
    }

    /** @return list<string> */
    public function origins(Realm $realm, Context $context): array
    {
        $origins = [$this->toOrigin($this->appUrl)];

        if ($realm === Realm::Customer) {
            foreach ($this->domains->origins($context) as $origin) {
                $origins[] = $origin;
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

        $origin = $parts['scheme'] . '://' . strtolower($parts['host']);
        if (isset($parts['port'])) {
            $origin .= ':' . $parts['port'];
        }

        return $origin;
    }
}
