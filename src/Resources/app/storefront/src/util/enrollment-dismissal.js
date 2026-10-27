/**
 * Dismissal rules of the passkey enrollment prompt. Pure: no DOM, no storage.
 * state: { count, snoozedUntil } or null when never dismissed.
 */
export const SNOOZE_MS = 30 * 24 * 60 * 60 * 1000;
export const MAX_DISMISSALS = 3;

export function shouldShow(state, now) {
    if (state === null) {
        return true;
    }

    return state.count < MAX_DISMISSALS && now >= state.snoozedUntil;
}

export function dismiss(state, now) {
    return {
        count: (state?.count ?? 0) + 1,
        snoozedUntil: now + SNOOZE_MS,
    };
}

export function parseState(raw) {
    if (typeof raw !== 'string') {
        return null;
    }

    try {
        const state = JSON.parse(raw);
        if (
            state !== null
            && typeof state === 'object'
            && Number.isInteger(state.count)
            && state.count >= 0
            && Number.isFinite(state.snoozedUntil)
        ) {
            return { count: state.count, snoozedUntil: state.snoozedUntil };
        }
    } catch {
        // Unreadable storage content counts as never dismissed.
    }

    return null;
}
