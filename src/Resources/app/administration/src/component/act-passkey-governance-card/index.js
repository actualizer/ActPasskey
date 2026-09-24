import template from './act-passkey-governance-card.html.twig';

const { Component } = Shopware;

/**
 * Operator view of ANOTHER account's passkeys: list and revoke, nothing else. There is
 * deliberately no add or rename — enrollment stays with the account holder.
 */
Component.register('act-passkey-governance-card', {
    template,

    inject: ['passkeyApiService'],

    // By name, not Mixin.getByName(): this bundle can run before any mixin is registered.
    mixins: ['notification'],

    props: {
        realm: {
            type: String,
            required: true,
            validator: (value) => ['user', 'customer'].includes(value),
        },
        ownerId: {
            type: String,
            required: true,
        },
    },

    data() {
        return {
            passkeys: [],
            isLoading: false,
            revokeItem: null,
            verifyModalOpen: false,
        };
    },

    computed: {
        // Mirrors core: Users & permissions demands a password confirmation, the
        // customer detail does not.
        requiresStepUp() {
            return this.realm === 'user';
        },

        columns() {
            return [
                {
                    property: 'name',
                    dataIndex: 'name',
                    label: this.$t('act-passkey.manage.columnName'),
                    allowResize: true,
                    primary: true,
                },
                {
                    property: 'createdAt',
                    dataIndex: 'createdAt',
                    label: this.$t('act-passkey.manage.columnCreatedAt'),
                    allowResize: true,
                },
                {
                    property: 'lastUsedAt',
                    dataIndex: 'lastUsedAt',
                    label: this.$t('act-passkey.manage.columnLastUsedAt'),
                    allowResize: true,
                },
            ];
        },
    },

    watch: {
        ownerId: {
            handler() {
                this.loadPasskeys();
            },
            immediate: true,
        },
    },

    methods: {
        formatDate(value) {
            if (!value) {
                return '';
            }

            try {
                return Shopware.Filter.getByName('date')(value);
            } catch {
                return value;
            }
        },

        async loadPasskeys() {
            if (!this.ownerId) {
                return;
            }

            this.isLoading = true;
            try {
                const response = await this.passkeyApiService.governanceList(this.realm, this.ownerId);
                this.passkeys = response.credentials || [];
            } catch {
                this.createNotificationError({
                    message: this.$t('act-passkey.manage.error'),
                });
            } finally {
                this.isLoading = false;
            }
        },

        onRevoke(item) {
            this.revokeItem = item;
            if (this.requiresStepUp) {
                this.verifyModalOpen = true;
            }
        },

        onCancel() {
            this.revokeItem = null;
            this.verifyModalOpen = false;
        },

        onVerified(context) {
            this.verifyModalOpen = false;
            this.performRevoke(context);
        },

        onConfirm() {
            this.performRevoke(null);
        },

        async performRevoke(context) {
            const item = this.revokeItem;
            this.revokeItem = null;
            if (!item) {
                return;
            }

            this.isLoading = true;
            try {
                await this.passkeyApiService.governanceRevoke(this.realm, this.ownerId, item.id, context);
                this.createNotificationSuccess({
                    message: this.$t('act-passkey.governance.revokeSuccess'),
                });
                await this.loadPasskeys();
            } catch {
                this.createNotificationError({
                    message: this.$t('act-passkey.manage.error'),
                });
            } finally {
                this.isLoading = false;
            }
        },
    },
});
