/**
 * Seconds to wait from a throttled admin API response, or null. The API's error
 * envelope drops response headers, so the wait time is read from core's rate-limit
 * error in the body. Pure function: see util/base64url.js for why.
 */
export function rateLimitSeconds(error) {
    if (error?.response?.status !== 429) {
        return null;
    }

    const seconds = error.response.data?.errors?.[0]?.meta?.parameters?.seconds;

    return Number.isInteger(seconds) ? seconds : null;
}
