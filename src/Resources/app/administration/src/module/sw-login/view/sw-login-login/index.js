// Snippets live under `sw-login`: while logged out the snippet endpoint serves
// only the `sw-login` and `global` namespaces.
import template from './sw-login-login.html.twig';

const { Component } = Shopware;

Component.override('sw-login-login', {
    template,

    inject: ['loginService'],

    data() {
        return {
            isWebAuthnSupported: !!window.PublicKeyCredential,
        };
    },

    methods: {
        async onPasskeyLogin() {
            this.loginErrorMessage = '';
            this.$emit('is-loading');

            try {
                this.loginService.setRememberMe(this.rememberMe);
                await this.loginService.loginByPasskey();
                await this.handleLoginSuccess();
            } catch {
                // Core's own error banner: this component has no notification mixin.
                this.loginErrorMessage = this.$t('sw-login.act-passkey.error');
            } finally {
                this.$emit('is-not-loading');
            }
        },
    },
});
