<?php declare(strict_types=1);

namespace Actualize\Passkey\Controller;

use Actualize\Passkey\WebAuthn\Credential\CredentialRepository;
use Shopware\Core\Framework\Validation\DataValidationDefinition;
use Symfony\Component\Validator\Constraints\Length;

/**
 * The credential-name rule for every rename route. Validated through core's
 * DataValidator, so each API renders the violation in its own error envelope.
 */
final class CredentialNameValidation
{
    public static function definition(): DataValidationDefinition
    {
        $definition = new DataValidationDefinition('act_passkey.rename');
        $definition->add('name', new Length(max: CredentialRepository::MAX_NAME_LENGTH));

        return $definition;
    }
}
