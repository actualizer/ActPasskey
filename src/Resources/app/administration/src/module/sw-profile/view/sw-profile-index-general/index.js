import template from './sw-profile-index-general.html.twig';

import deDE from '../../../../snippet/de-DE.json';
import enGB from '../../../../snippet/en-GB.json';

Shopware.Locale.extend('de-DE', deDE);
Shopware.Locale.extend('en-GB', enGB);

const { Component } = Shopware;

// Same base64url <-> ArrayBuffer conversion as init/passkey-login-service.init.js,
// duplicated locally rather than shared: registration also needs to encode the
// attestation response, which the login (assertion) flow does not.
function base64UrlToBuffer(value) {
    const padding = '='.repeat((4 - (value.length % 4)) % 4);
    const base64 = (value + padding).replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const buffer = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        buffer[i] = binary.charCodeAt(i);
    }
    return buffer.buffer;
}

function bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i += 1) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

Component.override('sw-profile-index-general', {
    template,

    inject: ['passkeyApiService'],

    // Mixin by name, not by Mixin.getByName(): this bundle is loaded on the
    // login screen, where it is evaluated before `src/app/main` has registered
    // any mixin, so a lookup at import time throws. The name is resolved when
    // the component is built (long after boot). Reading a core registry at
    // import time is what breaks here — writing to one is fine.
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
        // The API sends ISO8601 with an explicit UTC offset; the core date filter
        // renders it in the timezone from the admin user's profile. Resolving the
        // filter here rather than at import time is deliberate: this bundle is
        // also evaluated on the login screen, before the filter registry exists.
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
            } catch {
                this.createNotificationError({
                    message: this.$t('act-passkey.manage.error'),
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
