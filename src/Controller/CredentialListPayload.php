<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller;

use Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialCollection;

/**
 * The one list shape every passkey listing returns, admin and store-api alike. Deliberately without key
 * material: no listing contains the credential id, public key, sign count or user handle.
 */
final class CredentialListPayload
{
    /**
     * @return list<array<string, mixed>>
     */
    public static function fromCollection(PasskeyCredentialCollection $credentials): array
    {
        $payload = [];
        foreach ($credentials as $credential) {
            $payload[] = [
                'id' => $credential->getId(),
                'name' => $credential->getName(),
                'aaguid' => $credential->getAaguid(),
                'transports' => $credential->getTransports(),
                'createdAt' => $credential->getCreatedAt()?->format(\DATE_ATOM),
                'lastUsedAt' => $credential->getLastUsedAt()?->format(\DATE_ATOM),
            ];
        }

        return $payload;
    }
}
