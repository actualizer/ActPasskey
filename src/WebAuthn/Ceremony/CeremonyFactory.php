<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Ceremony;

use Actualize\Passkey\WebAuthn\RelyingParty\OriginAllowlistProvider;
use Shopware\Core\Framework\Context;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;

/**
 * Builds the webauthn-lib CeremonyStepManagers for registration ("creation")
 * and authentication ("request"), pinning the allowed origins to the
 * server-derived allowlist from OriginAllowlistProvider (never the request
 * Host header). Algorithm (ES256/RS256) and attestation support (none) are
 * left at CeremonyStepManagerFactory's library defaults, which match this
 * plugin's `none`-attestation passkey setup.
 */
final class CeremonyFactory
{
    public function __construct(private readonly OriginAllowlistProvider $origins)
    {
    }

    public function creation(Context $context): CeremonyStepManager
    {
        return $this->factory($context)->creationCeremony();
    }

    public function request(Context $context): CeremonyStepManager
    {
        return $this->factory($context)->requestCeremony();
    }

    private function factory(Context $context): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($this->origins->origins($context));

        return $factory;
    }
}
