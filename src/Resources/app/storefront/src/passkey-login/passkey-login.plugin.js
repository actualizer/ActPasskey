const Plugin = window.PluginBaseClass;

/**
 * Reveals the "sign in with a passkey" button on the storefront account
 * login page (only when the browser supports WebAuthn) and drives the
 * usernameless authentication ceremony: fetch request options from the
 * challenge endpoint, resolve `navigator.credentials.get()`, then submit
 * the assertion as a real form POST so the server's 302 redirect performs
 * a normal browser navigation into the account area.
 *
 * Verified against the stock login form (vendor/shopware/storefront):
 * it POSTs without any CSRF token field and Shopware 6.7 has no CSRF
 * listener/twig node-visitor wired up for storefront forms, so this
 * plugin's POST needs no token either.
 */
export default class PasskeyLogin extends Plugin {
    init() {
        this.button = this.el.querySelector('[data-act-passkey-login-button]');
        this.errorBox = this.el.querySelector('[data-act-passkey-login-error]');
        this.challengeUrl = this.el.dataset.challengeUrl;
        this.loginUrl = this.el.dataset.loginUrl;
        this.errorText = this.el.dataset.errorText || '';

        if (!window.PublicKeyCredential || !this.button || !this.challengeUrl || !this.loginUrl) {
            // No WebAuthn support (or markup incomplete) -> leave the
            // wrapper hidden, the password form stays fully usable.
            return;
        }

        this.el.hidden = false;
        this.button.addEventListener('click', this._onClick.bind(this));
    }

    async _onClick() {
        this._hideError();

        try {
            const challengeResponse = await fetch(this.challengeUrl, {
                method: 'POST',
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
            });
            const { options, challengeId } = await challengeResponse.json();

            const publicKey = {
                ...options,
                challenge: this._base64UrlToBuffer(options.challenge),
                allowCredentials: (options.allowCredentials || []).map((credential) => ({
                    ...credential,
                    id: this._base64UrlToBuffer(credential.id),
                })),
            };

            const credential = await navigator.credentials.get({ publicKey });

            const assertion = {
                id: credential.id,
                rawId: this._bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: this._bufferToBase64Url(credential.response.clientDataJSON),
                    authenticatorData: this._bufferToBase64Url(credential.response.authenticatorData),
                    signature: this._bufferToBase64Url(credential.response.signature),
                    userHandle: credential.response.userHandle
                        ? this._bufferToBase64Url(credential.response.userHandle)
                        : null,
                },
                clientExtensionResults: credential.getClientExtensionResults
                    ? credential.getClientExtensionResults()
                    : {},
            };

            this._submitAssertion(assertion, challengeId);
        } catch {
            // User cancelled the WebAuthn prompt, no credential available,
            // or the challenge fetch failed -> never leave the user stuck,
            // show an inline error and let them fall back to the password form.
            this._showError();
        }
    }

    _submitAssertion(assertion, challengeId) {
        const form = document.createElement('form');
        form.method = 'post';
        form.action = this.loginUrl;
        form.hidden = true;

        const addField = (name, value) => {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = name;
            input.value = value;
            form.appendChild(input);
        };
        addField('passkey_response', JSON.stringify(assertion));
        addField('passkey_challenge_id', challengeId);

        document.body.appendChild(form);
        form.submit();
    }

    _showError() {
        if (!this.errorBox) {
            return;
        }
        this.errorBox.textContent = this.errorText;
        this.errorBox.hidden = false;
    }

    _hideError() {
        if (!this.errorBox) {
            return;
        }
        this.errorBox.hidden = true;
    }

    _base64UrlToBuffer(value) {
        const padding = '='.repeat((4 - (value.length % 4)) % 4);
        const base64 = (value + padding).replace(/-/g, '+').replace(/_/g, '/');
        const binary = atob(base64);
        const buffer = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) {
            buffer[i] = binary.charCodeAt(i);
        }
        return buffer.buffer;
    }

    _bufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i += 1) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
}
