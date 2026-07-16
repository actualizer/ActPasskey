import PasskeyApiService from '../service/passkey.api.service';

const { Application } = Shopware;

// The init container is resolved inside the provider, not at import time: this
// bundle is loaded on the login screen, where it is evaluated before the
// application has registered all initializers. Touching the container that
// early yields a half-built one (and pins it), which breaks the boot with
// "Cannot read properties of undefined (reading 'addModuleRoutes')". By the
// time the provider runs, the container is complete.
Application.addServiceProvider(
    'passkeyApiService',
    (container) => new PasskeyApiService(Application.getContainer('init').httpClient, container.loginService),
);
