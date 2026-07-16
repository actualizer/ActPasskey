/**
 * The two snippets used here live under the `sw-login` namespace instead of
 * `act-passkey`, because the login screen is unauthenticated: the snippet
 * endpoint drops every namespace outside of `sw-login` and `global` while no
 * valid token exists, so an `act-passkey.*` key would render as a raw key.
 * Everything shown after login stays in our own namespace.
 */
import template from './sw-login-login.html.twig';

import deDE from '../../../../snippet/de-DE.json';
import enGB from '../../../../snippet/en-GB.json';

Shopware.Locale.extend('de-DE', deDE);
Shopware.Locale.extend('en-GB', enGB);

const { Component } = Shopware;

Component.override('sw-login-login', {
    template,

    inject: ['loginService'],

    data() {
        return {
            passkeyError: false,
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
