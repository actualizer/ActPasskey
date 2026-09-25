// Snippets live under `sw-login`: while logged out the snippet endpoint serves
// only the `sw-login` and `global` namespaces.
import template from './sw-login-login.html.twig';

const { Component } = Shopware;

Component.override('sw-login-login', {
    template,

    inject: ['loginService'],

    data() {
        return {
            passkeyError: false,
            isWebAuthnSupported: !!window.PublicKeyCredential,
        };
    },

    methods: {
        async onPasskeyLogin() {
            this.passkeyError = false;
            this.$emit('is-loading');

            try {
                await this.loginService.loginByPasskey();
                await this.handleLoginSuccess();
                this.$emit('is-not-loading');
            } catch {
                this.passkeyError = true;
                this.createNotificationError({
                    message: this.$t('sw-login.act-passkey.error'),
                });
                this.$emit('is-not-loading');
            }
        },
    },
});
