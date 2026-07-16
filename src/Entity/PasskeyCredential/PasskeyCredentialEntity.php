<?php declare(strict_types=1);

namespace Actualize\Passkey\Entity\PasskeyCredential;

use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Framework\DataAbstractionLayer\Entity;
use Shopware\Core\Framework\DataAbstractionLayer\EntityIdTrait;
use Shopware\Core\System\User\UserEntity;

class PasskeyCredentialEntity extends Entity
{
    use EntityIdTrait;

    protected string $realm;

    protected ?string $userId = null;
    protected ?UserEntity $user = null;

    protected ?string $customerId = null;
    protected ?CustomerEntity $customer = null;

    protected string $credentialId;
    protected string $publicKey;
    protected int $signCount;
    protected string $userHandle;

    protected ?string $aaguid = null;

    /**
     * @var array<int, string>|null
     */
    protected ?array $transports = null;

    protected ?string $name = null;

    protected ?\DateTimeInterface $lastUsedAt = null;

    public function getRealm(): string
    {
        return $this->realm;
    }

    public function setRealm(string $realm): void
    {
        $this->realm = $realm;
    }

    public function getUserId(): ?string
    {
        return $this->userId;
    }

    public function setUserId(?string $userId): void
    {
        $this->userId = $userId;
    }

    public function getUser(): ?UserEntity
    {
        return $this->user;
    }

    public function setUser(?UserEntity $user): void
    {
        $this->user = $user;
    }

    public function getCustomerId(): ?string
    {
        return $this->customerId;
    }

    public function setCustomerId(?string $customerId): void
    {
        $this->customerId = $customerId;
    }

    public function getCustomer(): ?CustomerEntity
    {
        return $this->customer;
    }

    public function setCustomer(?CustomerEntity $customer): void
    {
        $this->customer = $customer;
    }

    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    public function setCredentialId(string $credentialId): void
    {
        $this->credentialId = $credentialId;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function setPublicKey(string $publicKey): void
    {
        $this->publicKey = $publicKey;
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    public function setSignCount(int $signCount): void
    {
        $this->signCount = $signCount;
    }

    public function getUserHandle(): string
    {
        return $this->userHandle;
    }

    public function setUserHandle(string $userHandle): void
    {
        $this->userHandle = $userHandle;
    }

    public function getAaguid(): ?string
    {
        return $this->aaguid;
    }

    public function setAaguid(?string $aaguid): void
    {
        $this->aaguid = $aaguid;
    }

    /**
     * @return array<int, string>|null
     */
    public function getTransports(): ?array
    {
        return $this->transports;
    }

    /**
     * @param array<int, string>|null $transports
     */
    public function setTransports(?array $transports): void
    {
        $this->transports = $transports;
    }

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(?string $name): void
    {
        $this->name = $name;
    }

    public function getLastUsedAt(): ?\DateTimeInterface
    {
        return $this->lastUsedAt;
    }

    public function setLastUsedAt(?\DateTimeInterface $lastUsedAt): void
    {
        $this->lastUsedAt = $lastUsedAt;
    }
}
