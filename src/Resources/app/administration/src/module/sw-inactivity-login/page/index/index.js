/**
 * Adds the passkey button to the inactivity screen — the dialog the
 * administration shows after an automatic logout. Without it, that screen is a
 * password-only dead end for anyone who signs in with a passkey.
 *
 * Snippets come from the `sw-login` namespace on purpose: the session is gone
 * here, so a reloaded inactivity screen gets its snippets unauthenticated, and
 * the endpoint then serves nothing but the `sw-login` and `global` namespaces.
 */
import template from './sw-inactivity-login.html.twig';

const { Component } = Shopware;

Component.override('sw-inactivity-login', {
    template,

    methods: {
        async onPasskeyLogin() {
            this.isLoading = true;
            this.passwordError = null;

            try {
                await this.loginService.loginByPasskey();

                // Same success path as the password login: notifies the other
                // tabs via the session channel and restores the previous route.
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
