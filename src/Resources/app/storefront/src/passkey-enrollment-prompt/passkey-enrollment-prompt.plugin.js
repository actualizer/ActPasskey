import { dismiss, parseState, shouldShow } from '../util/enrollment-dismissal';

const Plugin = window.PluginBaseClass;

/**
 * Invites the customer to add a passkey on the account overview.
 *
 * The card starts hidden and is shown only when WebAuthn exists and the customer
 * has not dismissed it recently. Storage may be unavailable: the card then shows
 * every time and "Not now" only hides it for the current view.
 */
export default class PasskeyEnrollmentPrompt extends Plugin {
    init() {
        this.storageKey = this.el.dataset.dismissKey || '';
        this.dismissButton = this.el.querySelector('[data-act-passkey-enrollment-prompt-dismiss]');

        if (!window.PublicKeyCredential || !this.dismissButton) {
            return;
        }

        if (!shouldShow(parseState(this._read()), Date.now())) {
            return;
        }

        this.dismissButton.addEventListener('click', this._onDismiss.bind(this));
        this.el.hidden = false;
    }

    _onDismiss() {
        this._write(JSON.stringify(dismiss(parseState(this._read()), Date.now())));
        this.el.hidden = true;

        // Hiding the focused button would drop focus to the document.
        const heading = document.querySelector('.account-welcome h1');
        if (heading) {
            heading.setAttribute('tabindex', '-1');
            heading.focus();
        }
    }

    _read() {
        try {
            return window.localStorage.getItem(this.storageKey);
        } catch {
            return null;
        }
    }

    _write(value) {
        try {
            window.localStorage.setItem(this.storageKey, value);
        } catch {
            // The card is hidden for this view regardless.
        }
    }
}
