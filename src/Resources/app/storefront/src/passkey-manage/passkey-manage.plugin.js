const Plugin = window.PluginBaseClass;

/**
 * Drives the "add a passkey" ceremony on the customer account profile page:
 * feature-detects WebAuthn support (hides the add-passkey form otherwise —
 * rename/delete need no WebAuthn and stay fully usable, spec §2.7), fetches
 * registration options from the challenge endpoint, resolves
 * `navigator.credentials.create()`, then submits the attestation plus the
 * password step-up field as a real form POST so the server's redirect
 * performs a normal browser navigation back to the profile page.
 *
 * Mirrors passkey-login.plugin.js for the fetch/submit style and the admin
 * sw-profile-index-general registration flow for the WebAuthn options
 * shaping (excludeCredentials, user.id conversion) — same ceremony, just
 * driven by a real form submit instead of the admin's Vue component.
 */
export default class PasskeyManage extends Plugin {
    init() {
        this.registerWrapper = this.el.querySelector('[data-act-passkey-manage-register]');
        this.form = this.el.querySelector('[data-act-passkey-manage-form]');
        this.passwordInput = this.el.querySelector('[data-act-passkey-manage-password]');
        this.errorBox = this.el.querySelector('[data-act-passkey-manage-error]');
        this.challengeUrl = this.el.dataset.challengeUrl;
        this.registerUrl = this.el.dataset.registerUrl;
        this.errorText = this.el.dataset.errorText || '';

        if (!window.PublicKeyCredential || !this.registerWrapper || !this.form || !this.challengeUrl || !this.registerUrl) {
            // No WebAuthn support (or markup incomplete) -> leave the
            // add-passkey form hidden, rename/delete stay fully usable.
            return;
        }

        this.registerWrapper.hidden = false;
        this.form.addEventListener('submit', this._onSubmit.bind(this));
    }

    async _onSubmit(event) {
        event.preventDefault();
        this._hideError();

        const nameInput = this.form.querySelector('input[name="name"]');
        const name = nameInput ? nameInput.value : '';
        const password = this.passwordInput.value;

        try {
            const challengeResponse = await fetch(this.challengeUrl, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({ password }),
            });

            if (!challengeResponse.ok) {
                this._showError();
                return;
            }

            const { options, challengeId } = await challengeResponse.json();

            const publicKey = {
                ...options,
                challenge: this._base64UrlToBuffer(options.challenge),
                user: {
                    ...options.user,
                    id: this._base64UrlToBuffer(options.user.id),
                },
                excludeCredentials: (options.excludeCredentials || []).map((credential) => ({
                    ...credential,
                    id: this._base64UrlToBuffer(credential.id),
                })),
            };

            const credential = await navigator.credentials.create({ publicKey });

            const attestation = {
                id: credential.id,
                rawId: this._bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: this._bufferToBase64Url(credential.response.clientDataJSON),
                    attestationObject: this._bufferToBase64Url(credential.response.attestationObject),
                },
                clientExtensionResults: credential.getClientExtensionResults
                    ? credential.getClientExtensionResults()
                    : {},
            };

            this._submitRegistration(attestation, challengeId, name, password);
        } catch {
            // User cancelled the WebAuthn prompt, no authenticator available,
            // or the challenge fetch failed -> never leave the user stuck,
            // show an inline error and let them retry.
            this._showError();
        }
    }

    _submitRegistration(attestation, challengeId, name, password) {
        const form = document.createElement('form');
        form.method = 'post';
        form.action = this.registerUrl;
        form.hidden = true;

        const addField = (fieldName, value) => {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = fieldName;
            input.value = value;
            form.appendChild(input);
        };
        addField('passkey_response', JSON.stringify(attestation));
        addField('passkey_challenge_id', challengeId);
        addField('name', name);
        addField('password', password);

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
