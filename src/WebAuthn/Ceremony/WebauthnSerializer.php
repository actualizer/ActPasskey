<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Ceremony;

use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * Thin wrapper that builds the webauthn-lib serializer exactly once from
 * WebauthnSerializerFactory. It serializes the option objects to the JSON the
 * browser's `navigator.credentials` call consumes, and deserializes the browser
 * `PublicKeyCredential` JSON back into the library value objects the real
 * validators operate on.
 *
 * Only `none` attestation is registered, matching this plugin's passkey setup.
 */
final class WebauthnSerializer
{
    private readonly SerializerInterface $serializer;

    public function __construct()
    {
        $attestationSupport = new AttestationStatementSupportManager([
            new NoneAttestationStatementSupport(),
        ]);

        $this->serializer = (new WebauthnSerializerFactory($attestationSupport))->create();
    }

    public function serializeOptions(
        PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions $options
    ): string {
        return $this->serializer->serialize($options, 'json');
    }

    public function deserializeCredential(string $json): PublicKeyCredential
    {
        return $this->serializer->deserialize($json, PublicKeyCredential::class, 'json');
    }
}
