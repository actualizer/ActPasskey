<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller\Admin;

use Actualize\Passkey\Entity\PasskeyCredential\PasskeyCredentialCollection;

/**
 * The one list shape every admin passkey listing returns. Deliberately without key
 * material: credential id, public key, sign count and user handle never leave the server.
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
