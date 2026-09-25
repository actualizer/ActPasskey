// Snippets live under `sw-login`: a reloaded inactivity screen fetches them
// without a session, and the endpoint then serves only `sw-login` and `global`.
import template from './sw-inactivity-login.html.twig';

const { Component } = Shopware;

Component.override('sw-inactivity-login', {
    template,

    data() {
        return {
            isWebAuthnSupported: !!window.PublicKeyCredential,
        };
    },

    methods: {
        async onPasskeyLogin() {
            this.isLoading = true;
            this.passwordError = null;

            try {
                // Core pins the password re-login to lastKnownUser; the usernameless
                // passkey prompt must not let another admin resume this session.
                await this.loginService.loginByPasskey(this.lastKnownUser);
                this.handleLoginSuccess();
            } catch {
                this.passwordError = {
                    detail: this.$t('sw-login.act-passkey.error'),
                };
            } finally {
                this.isLoading = false;
            }
        },
    },
});
