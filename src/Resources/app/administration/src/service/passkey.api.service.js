const ApiService = Shopware.Classes.ApiService;

/**
 * Admin self-service for the caller's own passkeys. Mutating calls accept an
 * optional `context` (as emitted by `sw-verify-user-modal`'s `verified` event)
 * and put its `user-verified` token on that request explicitly, rather than
 * relying on ambient auth state to happen to carry it.
 *
 * This is NOT an isolation guarantee: `sw-verify-user-modal` also calls
 * `loginService.setBearerAuthentication()`, which writes the same elevated
 * token into the shared auth cookie — so after one password confirmation it
 * stays the session's ambient token until the next rotation. That is core's
 * behaviour for every consumer of the modal and cannot be prevented here.
 * Passing the context explicitly still matters: it keeps a mutation from
 * silently depending on that side effect.
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
