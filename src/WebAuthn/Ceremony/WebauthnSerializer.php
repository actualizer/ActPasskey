<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Ceremony;

use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * Accepted attestation formats come from AttestationSupport.
 */
final class WebauthnSerializer
{
    /**
     * Hard ceiling on the browser credential JSON before it is parsed. A real
     * WebAuthn assertion/attestation (even a packed one carrying a certificate chain)
     * is a few KB; 64 KiB is far above any legitimate response but caps a
     * multi-megabyte payload before the deserializer allocates it.
     */
    public const MAX_CREDENTIAL_JSON_BYTES = 65536;

    private readonly SerializerInterface $serializer;

    public function __construct()
    {
        $this->serializer = (new WebauthnSerializerFactory(AttestationSupport::manager()))->create();
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
