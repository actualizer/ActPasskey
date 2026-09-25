/**
 * base64url <-> ArrayBuffer for the WebAuthn JSON wire format. Pure functions
 * only: this bundle also runs on the login screen, before the administration has
 * booted, so nothing here may touch a Shopware registry.
 */
export function base64UrlToBuffer(value) {
    const padding = '='.repeat((4 - (value.length % 4)) % 4);
    const base64 = (value + padding).replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const buffer = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        buffer[i] = binary.charCodeAt(i);
    }
    return buffer.buffer;
}

export function bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i += 1) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
