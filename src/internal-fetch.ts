export type FetchFunction = (input: string | URL | Request, options?: RequestInit) => Promise<Response>;

function urlOfInput(input: string | URL | Request): string {
    if (input instanceof Request) return input.url;
    if (input instanceof URL) return input.href;
    return new URL(input).href;
}

/**
 * oidc-provider makes its outgoing calls with an agent that rejects private, loopback
 * and non publicly routable addresses (SSRF protection). That protection prevents
 * notifying services on an internal network through the back-channel.
 *
 * This function skips the protection only for the URLs isAllowed accepts, which come
 * from the configuration of the registered clients. Any other destination keeps the protection.
 * The other options set by oidc-provider (timeout, headers) are kept.
 */
export function createFetchWithInternalDestinations(isAllowed: (url: string) => Promise<boolean>): FetchFunction {
    return async function (input: string | URL | Request, options?: RequestInit): Promise<Response> {
        if (!await isAllowed(urlOfInput(input))) {
            return fetch(input, options);
        }
        var optionsWithoutProtection: RequestInit = { ...options, dispatcher: undefined };
        return fetch(input, optionsWithoutProtection);
    };
}
