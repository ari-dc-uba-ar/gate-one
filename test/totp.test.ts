import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { decryptTotpSecret, encryptTotpSecret, generateTotpSecret, parseTotpKey, totpCodeAt, totpUri, verifyTotpCode } from '../src/totp.ts';

describe('totp', function (): void {
    var secret: string = generateTotpSecret();
    var now: number = Date.now();

    it('generates 160 bit secrets in base32', function (): void {
        assert.match(secret, /^[A-Z2-7]{32}$/);
        assert.notEqual(generateTotpSecret(), secret);
    });

    it('builds the otpauth URI the authenticator apps read', function (): void {
        var uri: URL = new URL(totpUri('ana', secret));
        assert.equal(uri.protocol, 'otpauth:');
        assert.equal(uri.host, 'totp');
        assert.equal(decodeURIComponent(uri.pathname), '/gate-one:ana');
        assert.equal(uri.searchParams.get('secret'), secret);
        assert.equal(uri.searchParams.get('issuer'), 'gate-one');
        assert.equal(uri.searchParams.get('digits'), '6');
        assert.equal(uri.searchParams.get('period'), '30');
    });

    it('accepts the current code and the ones of the adjacent steps, and returns the step', function (): void {
        var step: number = Math.floor(now / 30000);
        assert.equal(verifyTotpCode('ana', secret, totpCodeAt('ana', secret, now), now), step);
        assert.equal(verifyTotpCode('ana', secret, totpCodeAt('ana', secret, now - 30000), now), step - 1);
        assert.equal(verifyTotpCode('ana', secret, totpCodeAt('ana', secret, now + 30000), now), step + 1);
    });

    it('rejects codes outside the window, of another secret, or malformed', function (): void {
        assert.equal(verifyTotpCode('ana', secret, totpCodeAt('ana', secret, now - 90000), now), undefined);
        assert.equal(verifyTotpCode('ana', secret, totpCodeAt('ana', generateTotpSecret(), now), now), undefined);
        assert.equal(verifyTotpCode('ana', secret, '12345', now), undefined);
        assert.equal(verifyTotpCode('ana', secret, 'abcdef', now), undefined);
    });

    it('ignores spaces in the code', function (): void {
        var code: string = totpCodeAt('ana', secret, now);
        assert.notEqual(verifyTotpCode('ana', secret, code.slice(0, 3) + ' ' + code.slice(3), now), undefined);
    });

    describe('secret encryption', function (): void {
        var key: Buffer = randomBytes(32);

        it('encrypts and decrypts', function (): void {
            var encrypted: string = encryptTotpSecret(key, 'ana', secret);
            assert.ok(!encrypted.includes(secret));
            assert.equal(decryptTotpSecret(key, 'ana', encrypted), secret);
        });

        it('fails with another key or another user', function (): void {
            var encrypted: string = encryptTotpSecret(key, 'ana', secret);
            assert.throws(function (): void { decryptTotpSecret(randomBytes(32), 'ana', encrypted); }, /cannot be decrypted/);
            assert.throws(function (): void { decryptTotpSecret(key, 'bea', encrypted); }, /cannot be decrypted/);
        });

        it('requires a 32 byte key', function (): void {
            assert.equal(parseTotpKey(key.toString('base64')).length, 32);
            assert.throws(function (): void { parseTotpKey(randomBytes(16).toString('base64')); }, /AUTH_TOTP_KEY/);
        });
    });
});
