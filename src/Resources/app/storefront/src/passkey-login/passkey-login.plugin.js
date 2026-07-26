const Plugin = window.PluginBaseClass;

/**
 * Usernameless passkey login on the storefront account login page.
 *
 * The assertion goes out as a real form POST so the server's 302 redirect is a
 * normal browser navigation. Shopware 6.7 wires no CSRF listener for storefront
 * forms, so this POST carries no token either.
 */
export default class PasskeyLogin extends Plugin {
    init() {
        this.button = this.el.querySelector('[data-act-passkey-login-button]');
        this.errorBox = this.el.querySelector('[data-act-passkey-login-error]');
        this.challengeUrl = this.el.dataset.challengeUrl;
        this.loginUrl = this.el.dataset.loginUrl;
        this.errorText = this.el.dataset.errorText || '';

        if (!window.PublicKeyCredential || !this.button || !this.challengeUrl || !this.loginUrl) {
            // Leave the wrapper hidden: the password form stays fully usable.
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
            // Cancelled prompt, no credential, or a failed fetch: never leave the
            // user stuck without the password fallback.
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

        // Carry the surrounding login form's redirect fields, so a passkey login
        // from checkout/review cards returns the user to where they were.
        this._carryRedirectFields(addField);

        document.body.appendChild(form);
        form.submit();
    }

    _carryRedirectFields(addField) {
        const loginForm = this.el.closest('form');
        if (!loginForm) {
            return;
        }

        ['redirectTo', 'redirectParameters'].forEach((name) => {
            const field = loginForm.querySelector(`input[name="${name}"]`);
            if (field && field.value !== '') {
                addField(name, field.value);
            }
        });
    }

    _showError() {
        if (!this.errorBox) {
            return;
        }
        // Reveal the region first, then write into it: a role="alert" that receives
        // its text while still hidden is not reliably announced.
        this.errorBox.hidden = false;
        this.errorBox.textContent = this.errorText;
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
