import PasskeyLogin from './passkey-login/passkey-login.plugin';
import PasskeyManage from './passkey-manage/passkey-manage.plugin';

const PluginManager = window.PluginManager;
PluginManager.register('ActPasskeyLogin', PasskeyLogin, '[data-act-passkey-login]');
PluginManager.register('ActPasskeyManage', PasskeyManage, '[data-act-passkey-manage]');
