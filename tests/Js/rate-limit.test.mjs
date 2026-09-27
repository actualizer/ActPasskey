import { test } from 'node:test';
import assert from 'node:assert/strict';

const { rateLimitSeconds } = await import(
    new URL('../../src/Resources/app/administration/src/util/rate-limit.js', import.meta.url)
);

const apiError = (status, errors) => ({ response: { status, data: { errors } } });

test('reads the wait time from a throttled admin API response', () => {
    const error = apiError(429, [{ status: '429', meta: { parameters: { seconds: 42 } } }]);
    assert.equal(rateLimitSeconds(error), 42);
});

test('returns null for anything that is not a throttle with a usable wait time', () => {
    assert.equal(rateLimitSeconds(apiError(400, [{ meta: { parameters: { seconds: 42 } } }])), null);
    assert.equal(rateLimitSeconds(apiError(429, [{ meta: {} }])), null);
    assert.equal(rateLimitSeconds(apiError(429, [{ meta: { parameters: { seconds: '42' } } }])), null);
    assert.equal(rateLimitSeconds(apiError(429, [])), null);
    assert.equal(rateLimitSeconds(new Error('network')), null);
    assert.equal(rateLimitSeconds(undefined), null);
});
