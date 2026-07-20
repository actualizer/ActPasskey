<?php declare(strict_types=1);
namespace Actualize\Passkey\WebAuthn\RelyingParty;

use Actualize\Passkey\WebAuthn\Credential\Realm;
use Shopware\Core\Framework\Context;
use Shopware\Core\System\SystemConfig\SystemConfigService;

/**
 * Resolves the WebAuthn relying party id for a request host.
 *
 * Rule order is binding: the APP_URL branch runs before the sales channel list,
 * otherwise a shop whose APP_URL host is also a sales channel domain would get a
 * different rp id depending on the data, invalidating its credentials.
 */
final class RelyingPartyIdResolver
{
    private readonly string $appHost;

    public function __construct(
        string $appUrl,
        private readonly SalesChannelDomainProvider $domains,
        private readonly SystemConfigService $systemConfig,
    ) {
        $this->appHost = strtolower((string) parse_url($appUrl, PHP_URL_HOST));
    }

    public function resolve(Realm $realm, string $host, Context $context): string
    {
        $host = strtolower(trim($host));

        if ($realm === Realm::Customer) {
            $parent = $this->broadenParent();
            if ($parent !== null && $this->isWithin($host, $parent)) {
                return $parent;
            }
        }

        if ($this->isWithin($host, $this->appHost)) {
            return $this->appHost;
        }

        // The admin deliberately stops here: it always runs on APP_URL, so widening
        // it to customer domains would only make its credential usable in more places.
        if ($realm === Realm::Customer && in_array($host, $this->domains->hosts($context), true)) {
            return $host;
        }

        throw new UnsupportedHostException($host);
    }

    private function broadenParent(): ?string
    {
        $configured = $this->systemConfig->get('ActPasskey.config.broadenParentDomain');
        if (!is_string($configured)) {
            return null;
        }

        $parent = strtolower(trim($configured));
        if ($parent === '') {
            return null;
        }

        // A parent the APP_URL host does not fall under would yield an rp id no realm
        // can be reached from, silently invalidating every newly created passkey.
        return $this->isWithin($this->appHost, $parent) ? $parent : null;
    }

    private function isWithin(string $host, string $suffix): bool
    {
        if ($suffix === '') {
            return false;
        }

        return $host === $suffix || str_ends_with($host, '.' . $suffix);
    }
}
