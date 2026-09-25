/**
 * Decorates the core `loginService` with `loginByPasskey()` so a usernameless
 * WebAuthn login yields an identical admin session as the password flow
 * (same `setBearerAuthentication` call, same cookie/refresh handling).
 */
const { Application } = Shopware;

function base64UrlToBuffer(value) {
    const padding = '='.repeat((4 - (value.length % 4)) % 4);
    const base64 = (value + padding).replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const buffer = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        buffer[i] = binary.charCodeAt(i);
    }
    return buffer.buffer;
}

function bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i += 1) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

Application.addServiceProviderDecorator('loginService', (loginService) => {
    const httpClient = Application.getContainer('init').httpClient;
    const context = Shopware.Context.api;

    /**
     * @param {string} [expectedUsername] pins the login to this user (inactivity screen);
     *     the grant refuses any other user's passkey before issuing a token.
     */
    loginService.loginByPasskey = async function loginByPasskey(expectedUsername = '') {
        if (!window.PublicKeyCredential) {
            throw new Error('passkey-unsupported');
        }

        const challengeResponse = await httpClient.post(
            '/_action/act-passkey/admin/login-challenge',
            {},
            { baseURL: context.apiPath },
        );
        const { options, challengeId } = challengeResponse.data;

        const publicKey = {
            ...options,
            challenge: base64UrlToBuffer(options.challenge),
            allowCredentials: (options.allowCredentials || []).map((credential) => ({
                ...credential,
                id: base64UrlToBuffer(credential.id),
            })),
        };

        const credential = await navigator.credentials.get({ publicKey });

        const assertion = {
            id: credential.id,
            rawId: bufferToBase64Url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
                authenticatorData: bufferToBase64Url(credential.response.authenticatorData),
                signature: bufferToBase64Url(credential.response.signature),
                userHandle: credential.response.userHandle ? bufferToBase64Url(credential.response.userHandle) : null,
            },
            clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
        };

        const tokenResponse = await httpClient.post(
            '/oauth/token',
            {
                grant_type: 'passkey',
                client_id: 'administration',
                scope: 'write',
                passkey_response: JSON.stringify(assertion),
                passkey_challenge_id: challengeId,
                passkey_expected_username: expectedUsername,
            },
            { baseURL: context.apiPath },
        );

        // Same sequence as core's loginByUsername(): renew the activity timestamp
        // before storing the token, or a stale one from before an inactivity logout
        // ends the fresh session again; then flag the login so
        // notifyOnLoginListener() runs the registered login listeners. Both reads
        // happen at click time, after boot — never hoist them to module level.
        Shopware.Service('userActivityService').updateLastUserActivity();

        const auth = loginService.setBearerAuthentication({
            access: tokenResponse.data.access_token,
            refresh: tokenResponse.data.refresh_token,
            expiry: tokenResponse.data.expires_in,
        });

        sessionStorage.setItem('redirectFromLogin', 'true');

        return auth;
    };

    return loginService;
});
