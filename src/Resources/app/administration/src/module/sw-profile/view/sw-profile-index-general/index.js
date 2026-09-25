import template from './sw-profile-index-general.html.twig';
import { base64UrlToBuffer, bufferToBase64Url } from '../../../../util/base64url';

const { Component } = Shopware;

Component.override('sw-profile-index-general', {
    template,

    inject: ['passkeyApiService'],

    // By name, not Mixin.getByName(): on the login screen this bundle runs
    // before any mixin is registered, so a lookup at import time throws.
    mixins: ['notification'],

    data() {
        return {
            passkeys: [],
            isPasskeyLoading: false,
            isWebAuthnSupported: !!window.PublicKeyCredential,
            passkeyVerifyModalOpen: false,
            pendingAction: null,
            passkeyRenameItem: null,
            passkeyRenameValue: '',
        };
    },

    computed: {
        passkeyColumns() {
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

    created() {
        this.loadPasskeys();
    },

    methods: {
        // Renders the API's ISO8601 in the user profile's timezone. Resolved
        // here, not at import time: on the login screen the registry is empty.
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
            this.isPasskeyLoading = true;
            try {
                const response = await this.passkeyApiService.list();
                this.passkeys = response.credentials || [];
            } catch {
                this.createNotificationError({
                    message: this.$t('act-passkey.manage.error'),
                });
            } finally {
                this.isPasskeyLoading = false;
            }
        },

        onPasskeyRegister() {
            this.pendingAction = { type: 'register' };
            this.passkeyVerifyModalOpen = true;
        },

        onPasskeyRename(item) {
            this.passkeyRenameItem = item;
            this.passkeyRenameValue = item.name;
        },

        onPasskeyRenameCancel() {
            this.passkeyRenameItem = null;
            this.passkeyRenameValue = '';
        },

        onPasskeyRenameConfirm() {
            const name = this.passkeyRenameValue.trim();
            if (!name || !this.passkeyRenameItem) {
                return;
            }

            // The unchanged name is no rename: close without a password step-up or request.
            if (name === (this.passkeyRenameItem.name || '').trim()) {
                this.onPasskeyRenameCancel();
                return;
            }

            this.pendingAction = { type: 'rename', id: this.passkeyRenameItem.id, name };
            this.passkeyRenameItem = null;
            this.passkeyRenameValue = '';
            this.passkeyVerifyModalOpen = true;
        },

        onPasskeyDelete(item) {
            this.pendingAction = { type: 'delete', id: item.id };
            this.passkeyVerifyModalOpen = true;
        },

        onPasskeyVerifyClosed() {
            this.passkeyVerifyModalOpen = false;
            this.pendingAction = null;
        },

        async onPasskeyVerified(context) {
            this.passkeyVerifyModalOpen = false;
            const action = this.pendingAction;
            this.pendingAction = null;

            if (!action) {
                return;
            }

            if (action.type === 'register') {
                await this.performRegister(context);
            } else if (action.type === 'rename') {
                await this.performRename(action.id, action.name, context);
            } else if (action.type === 'delete') {
                await this.performDelete(action.id, context);
            }
        },

        async performRegister(context) {
            if (!window.PublicKeyCredential) {
                return;
            }

            this.isPasskeyLoading = true;
            // What the browser's passkey manager shows as the account. The email is
            // unambiguous (`username` is often a bare first name), and the realm
            // suffix keeps an admin passkey apart from a customer passkey the same
            // person may hold: both live on the same RP-ID, so without it the
            // chooser would show two identical entries. Purely a label — the server
            // resolves the account from the stored credential row, never from this.
            const displayName = `${this.user.firstName} ${this.user.lastName}`.trim();
            const account = this.user.email || this.user.username;
            const userName = `${account} ${this.$t('act-passkey.manage.adminRealmSuffix')}`;

            try {
                const { options, challengeId } = await this.passkeyApiService.registerChallenge(
                    displayName,
                    userName,
                    context,
                );

                const publicKey = {
                    ...options,
                    challenge: base64UrlToBuffer(options.challenge),
                    user: {
                        ...options.user,
                        id: base64UrlToBuffer(options.user.id),
                    },
                    excludeCredentials: (options.excludeCredentials || []).map((credential) => ({
                        ...credential,
                        id: base64UrlToBuffer(credential.id),
                    })),
                };

                const credential = await navigator.credentials.create({ publicKey });

                const attestation = {
                    id: credential.id,
                    rawId: bufferToBase64Url(credential.rawId),
                    type: credential.type,
                    response: {
                        clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
                        attestationObject: bufferToBase64Url(credential.response.attestationObject),
                    },
                    clientExtensionResults: credential.getClientExtensionResults
                        ? credential.getClientExtensionResults()
                        : {},
                };

                await this.passkeyApiService.register(
                    {
                        passkey_response: JSON.stringify(attestation),
                        passkey_challenge_id: challengeId,
                        name: '',
                        displayName,
                        userName,
                    },
                    context,
                );

                this.createNotificationSuccess({
                    message: this.$t('act-passkey.manage.registerSuccess'),
                });
                await this.loadPasskeys();
            } catch {
                this.createNotificationError({
                    message: this.$t('act-passkey.manage.error'),
                });
            } finally {
                this.isPasskeyLoading = false;
            }
        },

        async performRename(id, name, context) {
            this.isPasskeyLoading = true;
            try {
                await this.passkeyApiService.rename(id, name, context);
                await this.loadPasskeys();
            } catch (error) {
                // The only validation on rename is the name length.
                const tooLong = error?.response?.status === 400;
                this.createNotificationError({
                    message: tooLong
                        ? this.$t('act-passkey.manage.nameTooLong', { max: 128 })
                        : this.$t('act-passkey.manage.error'),
                });
                this.isPasskeyLoading = false;
            }
        },

        async performDelete(id, context) {
            this.isPasskeyLoading = true;
            try {
                await this.passkeyApiService.remove(id, context);
                this.createNotificationSuccess({
                    message: this.$t('act-passkey.manage.deleteSuccess'),
                });
                await this.loadPasskeys();
            } catch {
                this.createNotificationError({
                    message: this.$t('act-passkey.manage.error'),
                });
                this.isPasskeyLoading = false;
            }
        },
    },
});
