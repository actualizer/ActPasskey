<?php declare(strict_types=1);
namespace Actualize\Passkey\WebAuthn\Credential;
enum Realm: string {
    case Admin = 'admin';
    case Customer = 'customer';
}
