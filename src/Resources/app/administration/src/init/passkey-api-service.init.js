import PasskeyApiService from '../service/passkey.api.service';

const { Application } = Shopware;
const initContainer = Application.getContainer('init');

Application.addServiceProvider(
    'passkeyApiService',
    (container) => new PasskeyApiService(initContainer.httpClient, container.loginService),
);
