import PasskeyLogin from './passkey-login/passkey-login.plugin';

const PluginManager = window.PluginManager;
PluginManager.register('ActPasskeyLogin', PasskeyLogin, '[data-act-passkey-login]');
