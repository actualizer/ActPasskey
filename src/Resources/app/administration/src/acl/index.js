/**
 * Role rows for operator revocation, each offering only "delete".
 *
 * Registered through a decorator, never via Shopware.Service('privileges') at top level:
 * this bundle is always evaluated before app/main (it is also injected on the login
 * screen), where reading the service container would pin a half-built one and kill the
 * boot. The decorator runs when core first creates the privileges service.
 */
Shopware.Application.addServiceProviderDecorator('privileges', (privileges) => {
    privileges.addPrivilegeMappingEntry({
        category: 'permissions',
        parent: 'customers',
        key: 'act_passkey_customer',
        roles: {
            deleter: {
                privileges: ['act_passkey.revoke_customer'],
                dependencies: ['customer.viewer'],
            },
        },
    });

    privileges.addPrivilegeMappingEntry({
        category: 'permissions',
        parent: 'settings',
        key: 'act_passkey_user',
        roles: {
            deleter: {
                privileges: ['act_passkey.revoke_user'],
                dependencies: ['users_and_permissions.viewer'],
            },
        },
    });

    return privileges;
});
