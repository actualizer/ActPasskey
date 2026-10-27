import { test } from 'node:test';
import assert from 'node:assert/strict';

const { SNOOZE_MS, MAX_DISMISSALS, shouldShow, dismiss, parseState } = await import(
    new URL('../../src/Resources/app/storefront/src/util/enrollment-dismissal.js', import.meta.url)
);

const now = 1_800_000_000_000;

test('shows the prompt when it was never dismissed', () => {
    assert.equal(shouldShow(null, now), true);
});

test('one dismissal snoozes the prompt for exactly SNOOZE_MS', () => {
    const state = dismiss(null, now);
    assert.equal(shouldShow(state, now), false);
    assert.equal(shouldShow(state, now + SNOOZE_MS - 1), false);
    assert.equal(shouldShow(state, now + SNOOZE_MS), true);
});

test('stops for good after MAX_DISMISSALS dismissals', () => {
    assert.equal(MAX_DISMISSALS, 3);
    let state = null;
    let at = now;
    for (let i = 0; i < MAX_DISMISSALS; i += 1) {
        assert.equal(shouldShow(state, at), true);
        state = dismiss(state, at);
        at += SNOOZE_MS;
    }
    assert.equal(state.count, 3);
    assert.equal(shouldShow(state, now + 10 * SNOOZE_MS), false);
});

test('parseState rejects anything that is not a stored state', () => {
    assert.equal(parseState('not json'), null);
    assert.equal(parseState('{"count":"x"}'), null);
    assert.equal(parseState(null), null);
});

test('parseState round-trips a dismissed state', () => {
    const state = dismiss(null, now);
    assert.deepEqual(parseState(JSON.stringify(state)), state);
});
