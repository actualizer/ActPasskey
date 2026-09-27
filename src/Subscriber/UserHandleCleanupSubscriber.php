<?php declare(strict_types=1);

namespace Actualize\Passkey\Subscriber;

use Actualize\Passkey\WebAuthn\Credential\Realm;
use Doctrine\DBAL\ArrayParameterType;
use Doctrine\DBAL\Connection;
use Shopware\Core\Checkout\Customer\CustomerEvents;
use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityDeletedEvent;
use Shopware\Core\System\User\UserEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * A deleted account's credentials go through the FK cascade; its user handle has no
 * FK, because `account_id` points at a user or a customer depending on the realm. The
 * handle is removed here instead, scoped to the realm of the deleted entity.
 *
 * Plain DBAL: the handle definition denies writes outside system scope, and this runs
 * inside another entity's write.
 *
 * Known limit: a delete that bypasses the DAL (raw SQL) fires no event and leaves its
 * handle behind. Such a row holds only a random handle and an account id, no PII.
 */
final class UserHandleCleanupSubscriber implements EventSubscriberInterface
{
    public function __construct(private readonly Connection $connection)
    {
    }

    /**
     * @return array<string, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            UserEvents::USER_DELETED_EVENT => 'onUserDeleted',
            CustomerEvents::CUSTOMER_DELETED_EVENT => 'onCustomerDeleted',
        ];
    }

    public function onUserDeleted(EntityDeletedEvent $event): void
    {
        $this->deleteHandles(Realm::Admin, $event->getIds());
    }

    public function onCustomerDeleted(EntityDeletedEvent $event): void
    {
        $this->deleteHandles(Realm::Customer, $event->getIds());
    }

    /**
     * @param list<string> $accountIds
     */
    private function deleteHandles(Realm $realm, array $accountIds): void
    {
        if ($accountIds === []) {
            return;
        }

        $this->connection->executeStatement(
            'DELETE FROM `act_passkey_user_handle` WHERE `realm` = :realm AND `account_id` IN (:accountIds)',
            ['realm' => $realm->value, 'accountIds' => $accountIds],
            ['accountIds' => ArrayParameterType::STRING]
        );
    }
}
