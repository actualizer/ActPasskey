const ApiService = Shopware.Classes.ApiService;

/**
 * Admin self-service for the caller's own passkeys. Mutating calls take the
 * `context` from `sw-verify-user-modal`'s `verified` event and put its
 * user-verified token on the request explicitly, so no mutation silently
 * depends on ambient auth state. This is not an isolation guarantee: the modal
 * also writes that token into the shared auth cookie (core behaviour).
 */
class PasskeyApiService extends ApiService {
    constructor(httpClient, loginService, apiEndpoint = 'act-passkey') {
        super(httpClient, loginService, apiEndpoint);
        this.name = 'passkeyApiService';
    }

    _headers(context) {
        const headers = this.getBasicHeaders();
        if (context && context.authToken && context.authToken.access) {
            // One-shot user-verified token from sw-verify-user-modal.
            headers.Authorization = `Bearer ${context.authToken.access}`;
        }
        return headers;
    }

    list() {
        return this.httpClient
            .post('_action/act-passkey/admin/credentials', {}, { headers: this.getBasicHeaders() })
            .then((response) => ApiService.handleResponse(response));
    }

    registerChallenge(displayName, userName, context) {
        return this.httpClient
            .post('_action/act-passkey/admin/register-challenge', { displayName, userName }, { headers: this._headers(context) })
            .then((response) => ApiService.handleResponse(response));
    }

    register(payload, context) {
        return this.httpClient
            .post('_action/act-passkey/admin/register', payload, { headers: this._headers(context) })
            .then((response) => ApiService.handleResponse(response));
    }

    rename(id, name, context) {
        return this.httpClient
            .patch(`_action/act-passkey/admin/credentials/${id}`, { name }, { headers: this._headers(context) })
            .then((response) => ApiService.handleResponse(response));
    }

    remove(id, context) {
        return this.httpClient
            .delete(`_action/act-passkey/admin/credentials/${id}`, { headers: this._headers(context) })
            .then((response) => ApiService.handleResponse(response));
    }
}

export default PasskeyApiService;
