import { strict as assert } from 'node:assert';
import { formatMessage, i18n, lang, messages, setLang } from '../src/messages.ts';

describe('messages', function (): void {

    afterEach(function (): void {
        setLang('en');
    });

    it('every language translates every message', function (): void {
        var keys: string[] = Object.keys(i18n.messages.en).sort();
        Object.keys(i18n.messages).forEach(function (language: string): void {
            assert.deepEqual(Object.keys(i18n.messages[language]).sort(), keys, 'language ' + language);
        });
    });

    it('setLang changes the messages and the language', function (): void {
        setLang('es');
        assert.equal(lang, 'es');
        assert.equal(messages.signInButton, 'Ingresar');
        setLang('en');
        assert.equal(lang, 'en');
        assert.equal(messages.signInButton, 'Sign in');
    });

    it('setLang throws on an unknown language', function (): void {
        assert.throws(function (): void { setLang('xx'); }, /unknown language xx/);
        assert.equal(lang, 'en');
    });

    it('formatMessage replaces the placeholders', function (): void {
        assert.equal(formatMessage('user $1 created in $2', 'ana', '/tmp/users.json'), 'user ana created in /tmp/users.json');
        assert.equal(formatMessage('only $1', 'one', 'two'), 'only one');
        assert.equal(formatMessage('missing $2', 'one'), 'missing $2');
    });
});
