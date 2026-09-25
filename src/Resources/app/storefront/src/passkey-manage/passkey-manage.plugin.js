import { base64UrlToBuffer, bufferToBase64Url } from '../util/base64url';

const Plugin = window.PluginBaseClass;

/**
 * Adds a passkey on the customer account profile page.
 *
 * Without WebAuthn support the add form stays hidden; rename and delete need no
 * WebAuthn and remain usable. The attestation goes out as a real form POST so
 * the server's redirect is a normal browser navigation.
 */
export default class PasskeyManage extends Plugin {
    init() {
        this.registerWrapper = this.el.querySelector('[data-act-passkey-manage-register]');
        this.startButton = this.el.querySelector('[data-act-passkey-manage-start]');
        this.cancelButton = this.el.querySelector('[data-act-passkey-manage-cancel]');
        this.form = this.el.querySelector('[data-act-passkey-manage-form]');
        this.passwordInput = this.el.querySelector('[data-act-passkey-manage-password]');
        this.errorBox = this.el.querySelector('[data-act-passkey-manage-error]');
        this.challengeUrl = this.el.dataset.challengeUrl;
        this.registerUrl = this.el.dataset.registerUrl;
        this.errorText = this.el.dataset.errorText || '';

        this._initItems();

        if (!window.PublicKeyCredential || !this.registerWrapper || !this.form || !this.challengeUrl || !this.registerUrl) {
            return;
        }

        this.registerWrapper.hidden = false;
        this.form.addEventListener('submit', this._onSubmit.bind(this));
        this.startButton?.addEventListener('click', this._onStart.bind(this));
        this.cancelButton?.addEventListener('click', this._onCancel.bind(this));
    }

    // Runs before the WebAuthn check above: renaming and deleting need no
    // authenticator and stay available when the browser cannot do passkeys.
    _initItems() {
        this.el.querySelectorAll('[data-act-passkey-item]').forEach((item) => {
            const actions = item.querySelectorAll('[data-act-passkey-item-actions]');
            const renameForm = item.querySelector('[data-act-passkey-rename-form]');
            const deleteForm = item.querySelector('[data-act-passkey-delete-form]');
            const renameCancel = item.querySelector('[data-act-passkey-rename-cancel]');
            const deleteCancel = item.querySelector('[data-act-passkey-delete-cancel]');
            const renameToggle = item.querySelector('[data-act-passkey-rename-toggle]');
            const deleteToggle = item.querySelector('[data-act-passkey-delete-toggle]');

            if (!actions.length || !renameForm || !deleteForm) {
                return;
            }

            const setExpanded = (toggle, expanded) => {
                toggle?.setAttribute('aria-expanded', expanded ? 'true' : 'false');
            };

            // The toggles stay visible while their form is open: that is what makes
            // aria-expanded describe a control the user can still reach, and it gives
            // focus somewhere to return to when the form closes.
            const collapse = (focusTarget) => {
                renameForm.hidden = true;
                deleteForm.hidden = true;
                setExpanded(renameToggle, false);
                setExpanded(deleteToggle, false);
                focusTarget?.focus();
            };

            const expand = (form, toggle) => {
                renameForm.hidden = true;
                deleteForm.hidden = true;
                setExpanded(renameToggle, false);
                setExpanded(deleteToggle, false);
                form.hidden = false;
                setExpanded(toggle, true);
                form.querySelector('input')?.focus();
            };

            actions.forEach((action) => {
                action.hidden = false;
            });
            collapse();

            if (renameCancel) {
                renameCancel.hidden = false;
                renameCancel.addEventListener('click', () => collapse(renameToggle));
            }

            if (deleteCancel) {
                deleteCancel.hidden = false;
                deleteCancel.addEventListener('click', () => collapse(deleteToggle));
            }

            renameToggle?.addEventListener('click', () => {
                if (renameForm.hidden) {
                    expand(renameForm, renameToggle);
                } else {
                    collapse(renameToggle);
                }
            });

            deleteToggle?.addEventListener('click', () => {
                if (deleteForm.hidden) {
                    expand(deleteForm, deleteToggle);
                } else {
                    collapse(deleteToggle);
                }
            });
        });
    }

    _onStart() {
        if (!this.form.hidden) {
            this._onCancel();
            return;
        }

        this._hideError();
        this.form.hidden = false;
        this.startButton?.setAttribute('aria-expanded', 'true');
        this.passwordInput?.focus();
    }

    _onCancel() {
        this._hideError();
        this.form.hidden = true;

        if (this.passwordInput) {
            this.passwordInput.value = '';
        }

        this.startButton?.setAttribute('aria-expanded', 'false');
        this.startButton?.focus();
    }

    async _onSubmit(event) {
        event.preventDefault();
        this._hideError();

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
                challenge: base64UrlToBuffer(options.challenge),
                user: {
                    ...options.user,
                    id: base64UrlToBuffer(options.user.id),
                },
                excludeCredentials: (options.excludeCredentials || []).map((credential) => ({
                    ...credential,
                    id: base64UrlToBuffer(credential.id),
                })),
            };

            const credential = await navigator.credentials.create({ publicKey });

            const attestation = {
                id: credential.id,
                rawId: bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
                    attestationObject: bufferToBase64Url(credential.response.attestationObject),
                },
                clientExtensionResults: credential.getClientExtensionResults
                    ? credential.getClientExtensionResults()
                    : {},
            };

            this._submitRegistration(attestation, challengeId, password);
        } catch {
            // Cancelled prompt, no authenticator, or a failed fetch.
            this._showError();
        }
    }

    // Without a name the server labels the credential "Passkey".
    _submitRegistration(attestation, challengeId, password) {
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
        addField('password', password);

        document.body.appendChild(form);
        form.submit();
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
}
