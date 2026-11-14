/** Authentication context class (acr) of a sign-in with password only, and with a second factor. */
export const PASSWORD_ACR: string = 'pwd';
export const MFA_ACR: string = 'mfa';

/** A service asks for a second factor with acr_values=mfa (voluntary acr, as in OpenID Connect Core 3.1.2.1). */
export function requestsMfa(acrValues: unknown): boolean {
    return typeof acrValues === 'string' && acrValues.split(' ').includes(MFA_ACR);
}
