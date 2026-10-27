import PasskeyLogin from './passkey-login/passkey-login.plugin';
import PasskeyManage from './passkey-manage/passkey-manage.plugin';
import PasskeyEnrollmentPrompt from './passkey-enrollment-prompt/passkey-enrollment-prompt.plugin';

const PluginManager = window.PluginManager;
PluginManager.register('ActPasskeyLogin', PasskeyLogin, '[data-act-passkey-login]');
PluginManager.register('ActPasskeyManage', PasskeyManage, '[data-act-passkey-manage]');
PluginManager.register('ActPasskeyEnrollmentPrompt', PasskeyEnrollmentPrompt, '[data-act-passkey-enrollment-prompt]');
