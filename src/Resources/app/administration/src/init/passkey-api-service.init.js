import PasskeyApiService from '../service/passkey.api.service';

const { Application } = Shopware;

// Resolve the container inside the provider: on the login screen this bundle
// runs before all initializers are registered, and reading the container that
// early pins a half-built one, which kills the boot.
Application.addServiceProvider(
    'passkeyApiService',
    (container) => new PasskeyApiService(Application.getContainer('init').httpClient, container.loginService),
);
