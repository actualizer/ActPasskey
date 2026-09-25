<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Ceremony;

use Actualize\Passkey\WebAuthn\Credential\Realm;
use Actualize\Passkey\WebAuthn\RelyingParty\OriginAllowlistProvider;
use Shopware\Core\Framework\Context;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;

/**
 * Builds the webauthn-lib CeremonyStepManagers, pinning the allowed origins to the
 * server-derived allowlist for that realm — never the request Host header.
 */
final class CeremonyFactory
{
    public function __construct(private readonly OriginAllowlistProvider $origins)
    {
    }

    public function creation(Realm $realm, Context $context): CeremonyStepManager
    {
        return $this->factory($realm, $context)->creationCeremony();
    }

    public function request(Realm $realm, Context $context): CeremonyStepManager
    {
        return $this->factory($realm, $context)->requestCeremony();
    }

    private function factory(Realm $realm, Context $context): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins($this->origins->origins($realm, $context));
        // Same set as the serializer, or a parsed format still fails validation.
        $factory->setAttestationStatementSupportManager(AttestationSupport::manager());

        return $factory;
    }
}
