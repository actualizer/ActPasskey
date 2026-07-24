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
 * Only `none` attestation is registered, matching this plugin's passkey setup.
 */
final class WebauthnSerializer
{
    /**
     * Hard ceiling on the browser credential JSON before it is parsed. A real
     * WebAuthn assertion/attestation ("none" attestation here) is a few KB; 64 KiB
     * is far above any legitimate response but caps a multi-megabyte payload before
     * the deserializer allocates it.
     */
    public const MAX_CREDENTIAL_JSON_BYTES = 65536;

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
        if (\strlen($json) > self::MAX_CREDENTIAL_JSON_BYTES) {
            throw new \RuntimeException('Credential response exceeds the maximum allowed size.');
        }

        return $this->serializer->deserialize($json, PublicKeyCredential::class, 'json');
    }
}
