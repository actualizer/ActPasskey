import { test } from 'node:test';
import assert from 'node:assert/strict';

const modules = {
    administration: '../../src/Resources/app/administration/src/util/base64url.js',
    storefront: '../../src/Resources/app/storefront/src/util/base64url.js',
};

const bytes = (...values) => new Uint8Array(values).buffer;

for (const [bundle, path] of Object.entries(modules)) {
    const { base64UrlToBuffer, bufferToBase64Url } = await import(new URL(path, import.meta.url));

    test(`${bundle}: encodes without padding and with the url-safe alphabet`, () => {
        assert.equal(bufferToBase64Url(bytes()), '');
        assert.equal(bufferToBase64Url(bytes(0xf8)), '-A');         // 1 byte → would be "+A=="
        assert.equal(bufferToBase64Url(bytes(0xff, 0xff)), '__8');  // 2 bytes → would be "//8="
        assert.equal(bufferToBase64Url(bytes(0, 1, 2)), 'AAEC');    // 3 bytes → no padding at all
    });

    test(`${bundle}: decodes every padding length`, () => {
        assert.deepEqual(new Uint8Array(base64UrlToBuffer('-A')), new Uint8Array([0xf8]));
        assert.deepEqual(new Uint8Array(base64UrlToBuffer('__8')), new Uint8Array([0xff, 0xff]));
        assert.deepEqual(new Uint8Array(base64UrlToBuffer('AAEC')), new Uint8Array([0, 1, 2]));
    });

    test(`${bundle}: round-trips all 256 byte values`, () => {
        const all = new Uint8Array(256).map((_, i) => i);
        assert.deepEqual(new Uint8Array(base64UrlToBuffer(bufferToBase64Url(all.buffer))), all);
    });
}
