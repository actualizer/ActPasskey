<?php declare(strict_types=1);
namespace Actualize\Passkey\WebAuthn\Challenge;
enum ChallengePurpose: string {
    case Authentication = 'authentication';
    case Registration = 'registration';
}
