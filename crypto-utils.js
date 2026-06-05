'use strict';

/**
 * CryptoUtils – AES-256-GCM Verschlüsselung via Web Crypto API.
 * Kein externes Framework nötig, läuft in jedem modernen Browser.
 *
 * Format des verschlüsselten Payloads (Base64-kodiert):
 *   [ 16 Byte Salt ][ 12 Byte IV ][ n Byte Ciphertext+AuthTag ]
 */
var CryptoUtils = (function () {

    // PBKDF2-Iterationen: 100 000 ist NIST-Minimum, gut genug für mobil
    // (höhere Werte erhöhen Sicherheit, aber auch Login-Wartezeit)
    var ITERATIONS = 100000;
    var SALT_LEN   = 16;
    var IV_LEN     = 12;

    // ── Hilfsfunktionen ──────────────────────────────────────────────

    function toBase64(buffer) {
        var bytes = new Uint8Array(buffer);
        var bin   = '';
        for (var i = 0; i < bytes.length; i++) {
            bin += String.fromCharCode(bytes[i]);
        }
        return btoa(bin);
    }

    function fromBase64(b64) {
        var bin = atob(b64);
        var buf = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) {
            buf[i] = bin.charCodeAt(i);
        }
        return buf;
    }

    // ── Schlüsselableitung ───────────────────────────────────────────

    function deriveKey(password, salt) {
        var enc = new TextEncoder();
        return crypto.subtle.importKey(
            'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
        ).then(function (material) {
            return crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: ITERATIONS, hash: 'SHA-256' },
                material,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
        });
    }

    // ── Öffentliche API ──────────────────────────────────────────────

    /**
     * Verschlüsselt einen Klartext-String mit dem gegebenen Passwort.
     * Gibt einen Base64-String zurück, der direkt in data.json gespeichert werden kann.
     */
    function encrypt(plaintext, password) {
        var salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
        var iv   = crypto.getRandomValues(new Uint8Array(IV_LEN));
        var enc  = new TextEncoder();

        return deriveKey(password, salt).then(function (key) {
            return crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                enc.encode(plaintext)
            );
        }).then(function (cipher) {
            var combined = new Uint8Array(SALT_LEN + IV_LEN + cipher.byteLength);
            combined.set(salt, 0);
            combined.set(iv, SALT_LEN);
            combined.set(new Uint8Array(cipher), SALT_LEN + IV_LEN);
            return toBase64(combined);
        });
    }

    /**
     * Entschlüsselt einen Base64-Payload mit dem gegebenen Passwort.
     * Wirft einen Fehler, wenn das Passwort falsch ist (GCM-Authentifizierung schlägt fehl).
     */
    function decrypt(payload, password) {
        var data   = fromBase64(payload);
        var salt   = data.slice(0, SALT_LEN);
        var iv     = data.slice(SALT_LEN, SALT_LEN + IV_LEN);
        var cipher = data.slice(SALT_LEN + IV_LEN);

        return deriveKey(password, salt).then(function (key) {
            return crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                cipher
            );
        }).then(function (plain) {
            return new TextDecoder().decode(plain);
        });
    }

    return { encrypt: encrypt, decrypt: decrypt };
}());
