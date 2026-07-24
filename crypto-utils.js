'use strict';

/**
 * CryptoUtils – AES-256-GCM Verschlüsselung/Entschlüsselung via Web Crypto API.
 * Kein externes Framework nötig – läuft in jedem modernen Browser über HTTPS.
 *
 * Payload-Format (Base64-kodiert, steht als "payload"-Feld in data.json):
 *   [ 16 Byte Salt ][ 12 Byte IV ][ n Byte Ciphertext + 16 Byte Auth-Tag ]
 *
 * Schlüsselableitung:
 *   PBKDF2-HMAC-SHA-256, 10.000 Iterationen → 256-Bit AES-Schlüssel
 *   Identische Parameter wie in export_tool.py, damit beide Seiten kompatibel sind.
 */
var CryptoUtils = (function () {

    // PBKDF2-Parameter – müssen exakt mit export_tool.py übereinstimmen
    var ITERATIONS = 10000;  // Hashing-Runden: mehr = sicherer, aber langsamerer Login
    var SALT_LEN   = 16;     // Byte; zufällig pro Exportvorgang → gleiche Daten, anderer Payload
    var IV_LEN     = 12;     // Byte; GCM-Nonce, muss pro Schlüssel einmalig sein

    // ── Hilfsfunktionen ──────────────────────────────────────────────────────

    /** Wandelt einen ArrayBuffer/Uint8Array in einen Base64-String um. */
    function toBase64(buffer) {
        var bytes = new Uint8Array(buffer);
        var bin   = '';
        for (var i = 0; i < bytes.length; i++) {
            bin += String.fromCharCode(bytes[i]);
        }
        return btoa(bin);
    }

    /** Wandelt einen Base64-String in ein Uint8Array um. */
    function fromBase64(b64) {
        var bin = atob(b64);
        var buf = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) {
            buf[i] = bin.charCodeAt(i);
        }
        return buf;
    }

    // ── Schlüsselableitung ───────────────────────────────────────────────────

    /**
     * Leitet einen AES-256-GCM-Schlüssel aus Passwort + Salt ab (PBKDF2).
     * Gibt ein Promise zurück, das mit dem fertigen CryptoKey aufgelöst wird.
     */
    function deriveKey(password, salt) {
        var enc = new TextEncoder();
        // Schritt 1: Passwort als "raw"-Material in die Web Crypto API importieren
        return crypto.subtle.importKey(
            'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
        ).then(function (material) {
            // Schritt 2: PBKDF2 anwenden → 256-Bit AES-GCM-Schlüssel
            return crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: salt, iterations: ITERATIONS, hash: 'SHA-256' },
                material,
                { name: 'AES-GCM', length: 256 },
                false,              // Schlüssel nicht exportierbar
                ['encrypt', 'decrypt']
            );
        });
    }

    // ── Öffentliche API ──────────────────────────────────────────────────────

    /**
     * Verschlüsselt einen Klartext-String mit dem gegebenen Passwort.
     * Gibt einen Base64-String zurück, der direkt als "payload" in data.json
     * gespeichert werden kann.
     */
    function encrypt(plaintext, password) {
        // Neue zufällige Salt + IV für jeden Verschlüsselungsvorgang
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
            // Salt, IV und Ciphertext (inkl. Auth-Tag) zu einem Buffer zusammenführen
            var combined = new Uint8Array(SALT_LEN + IV_LEN + cipher.byteLength);
            combined.set(salt, 0);
            combined.set(iv, SALT_LEN);
            combined.set(new Uint8Array(cipher), SALT_LEN + IV_LEN);
            return toBase64(combined);
        });
    }

    /**
     * Entschlüsselt einen Base64-Payload aus data.json mit dem Benutzerpasswort.
     * Wirft einen Fehler wenn das Passwort falsch ist – AES-GCM prüft den
     * Auth-Tag und schlägt bei Manipulation oder falschem Schlüssel fehl.
     */
    function decrypt(payload, password) {
        // Payload aufteilen: Salt | IV | Ciphertext+AuthTag
        var data   = fromBase64(payload);
        var salt   = data.slice(0, SALT_LEN);
        var iv     = data.slice(SALT_LEN, SALT_LEN + IV_LEN);
        var cipher = data.slice(SALT_LEN + IV_LEN);

        return deriveKey(password, salt).then(function (key) {
            // GCM prüft den Auth-Tag – bei falschem Passwort wird hier ein Fehler geworfen
            return crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                cipher
            );
        }).then(function (plain) {
            return new TextDecoder().decode(plain);
        });
    }

    // Nur die beiden Kernfunktionen nach außen freigeben
    return { encrypt: encrypt, decrypt: decrypt };

}());
