<?php declare(strict_types=1);

namespace Actualize\Passkey\Entity\PasskeyUserHandle;

use Shopware\Core\Framework\DataAbstractionLayer\Entity;
use Shopware\Core\Framework\DataAbstractionLayer\EntityIdTrait;

class PasskeyUserHandleEntity extends Entity
{
    use EntityIdTrait;

    protected string $realm;

    protected string $accountId;

    protected string $userHandle;

    public function getRealm(): string
    {
        return $this->realm;
    }

    public function setRealm(string $realm): void
    {
        $this->realm = $realm;
    }

    public function getAccountId(): string
    {
        return $this->accountId;
    }

    public function setAccountId(string $accountId): void
    {
        $this->accountId = $accountId;
    }

    public function getUserHandle(): string
    {
        return $this->userHandle;
    }

    public function setUserHandle(string $userHandle): void
    {
        $this->userHandle = $userHandle;
    }
}
