<?php declare(strict_types=1);

namespace Actualize\Passkey\WebAuthn\Customer;

use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Customer\CustomerException;

/**
 * Re-implements the account checks the core applies on the PASSWORD login path
 * but not on AccountService::loginById(), which the passkey paths use: the
 * latter only filters active/guest/boundSalesChannel, and the core's
 * isCustomerConfirmed() is private, so the double-opt-in condition is mirrored
 * here. Without this, a passkey would be a stronger credential than a password.
 */
final class CustomerEligibilityGuard
{
    public function assertEligible(CustomerEntity $customer): void
    {
        if (!$customer->getActive()) {
            // Same exception the core raises for an unknown id: no existence oracle.
            throw CustomerException::customerNotFoundByIdException($customer->getId());
        }

        if ($customer->getDoubleOptInRegistration() && $customer->getDoubleOptInConfirmDate() === null) {
            throw CustomerException::customerOptinNotCompleted($customer->getId());
        }
    }
}
