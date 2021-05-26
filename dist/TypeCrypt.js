"use strict";
var TypeCrypt;
(function (TypeCrypt) {
    const PBKDF2_ITERATIONS = 100000;
    async function newSigningKeyPair() {
        let key = await window.crypto.subtle.generateKey({
            name: "ECDSA",
            namedCurve: "P-521",
        }, true, ["sign", "verify"]);
        return [new PrivateSigningKey(key.privateKey), new PublicSigningKey(key.publicKey)];
    }
    TypeCrypt.newSigningKeyPair = newSigningKeyPair;
    class PrivateSigningKey {
        constructor(key) {
            this.key = key;
        }
        async export() {
            return await crypto.subtle.exportKey("raw", this.key);
        }
        static async import(encodedString) {
            let ab = fromBase64String(encodedString);
            let key = await crypto.subtle.importKey("raw", ab, {
                name: "ECDSA",
                namedCurve: "P-521",
            }, true, ["sign"]);
            return new PrivateSigningKey(key);
        }
        async sign(data) {
            return await crypto.subtle.sign({
                name: "ECDSA",
                hash: { name: "SHA-256" },
            }, this.key, data);
        }
    }
    TypeCrypt.PrivateSigningKey = PrivateSigningKey;
    class PublicSigningKey {
        constructor(key) {
            this.key = key;
        }
        async export() {
            return await crypto.subtle.exportKey("raw", this.key);
        }
        static async import(encodedString) {
            let ab = fromBase64String(encodedString);
            let key = await crypto.subtle.importKey("raw", ab, {
                name: "ECDSA",
                namedCurve: "P-521",
            }, true, ["verify"]);
            return new PublicSigningKey(key);
        }
        async verify(data, signature) {
            return crypto.subtle.verify({
                name: "ECDSA",
                hash: { name: "SHA-256" },
            }, this.key, signature, data);
        }
    }
    TypeCrypt.PublicSigningKey = PublicSigningKey;
    async function newAESKey(passphrase) {
        let salt = randomBytes(32);
        return getAESKey(passphrase, salt);
    }
    TypeCrypt.newAESKey = newAESKey;
    async function getAESKey(passphrase, salt) {
        let keyMaterial = await getKeyMaterial(passphrase);
        let key = await window.crypto.subtle.deriveKey({
            "name": "PBKDF2",
            salt: salt,
            "iterations": PBKDF2_ITERATIONS,
            "hash": "SHA-256"
        }, keyMaterial, { "name": "AES-GCM", "length": 256 }, true, ["encrypt", "decrypt"]);
        return new AESKey(salt, key);
    }
    TypeCrypt.getAESKey = getAESKey;
    class AESKey {
        constructor(salt, key) {
            this.salt = salt;
            this.key = key;
        }
        async encrypt(data) {
            let iv = randomBytes(32);
            let cipherText = await window.crypto.subtle.encrypt({
                name: "AES-GCM",
                iv
            }, this.key, data);
            return new AESCrypted(iv, cipherText);
        }
        async decrypt(data) {
            let { iv, cipherText } = data;
            return await window.crypto.subtle.decrypt({
                name: "AES-GCM",
                iv
            }, this.key, cipherText);
        }
    }
    TypeCrypt.AESKey = AESKey;
    class AESCrypted {
        constructor(iv, cipherText) {
            this.iv = iv;
            this.cipherText = cipherText;
        }
        toString() {
            return `${toBase64String(this.iv)}:${toBase64String(this.cipherText)}`;
        }
        static fromString(encryptedString) {
            let parts = encryptedString.split(':');
            let [iv, cipherText] = parts.map(fromBase64String);
            return new AESCrypted(iv, cipherText);
        }
    }
    TypeCrypt.AESCrypted = AESCrypted;
    async function newEncryptionKeyPair() {
        let key = await window.crypto.subtle.generateKey({
            name: "ECDH",
            namedCurve: "P-521",
        }, true, ["deriveKey"]);
        return [new PrivateEncryptionKey(key.privateKey), new PublicEncryptionKey(key.publicKey)];
    }
    TypeCrypt.newEncryptionKeyPair = newEncryptionKeyPair;
    class PrivateEncryptionKey {
        constructor(key) {
            this.key = key;
        }
        async export() {
            return await crypto.subtle.exportKey("raw", this.key);
        }
        static async import(encodedString) {
            let ab = fromBase64String(encodedString);
            let key = await crypto.subtle.importKey("raw", ab, {
                name: "ECDH",
                namedCurve: "P-521",
            }, true, ["deriveKey"]);
            return new PrivateEncryptionKey(key);
        }
    }
    TypeCrypt.PrivateEncryptionKey = PrivateEncryptionKey;
    class PublicEncryptionKey {
        constructor(key) {
            this.key = key;
        }
        async export() {
            return await crypto.subtle.exportKey("raw", this.key);
        }
        static async import(encodedString) {
            let ab = fromBase64String(encodedString);
            let key = await crypto.subtle.importKey("raw", ab, {
                name: "ECDSA",
                namedCurve: "P-521",
            }, true, ["deriveKey"]);
            return new PublicEncryptionKey(key);
        }
    }
    TypeCrypt.PublicEncryptionKey = PublicEncryptionKey;
    async function deriveSharedKey(privateKey, publicKey) {
        let key = await window.crypto.subtle.deriveKey({
            name: "ECDH",
            public: publicKey.key
        }, privateKey.key, {
            name: "AES-GCM",
            length: 256
        }, false, ["encrypt", "decrypt"]);
        return new AESKey(new Uint8Array(), key);
    }
    TypeCrypt.deriveSharedKey = deriveSharedKey;
    async function getKeyMaterial(passphrase) {
        let keyMaterial = window.crypto.subtle.importKey("raw", passphrase, { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]);
        return keyMaterial;
    }
    function randomBytes(numOfBytes) {
        let bytes = new Uint8Array(numOfBytes);
        window.crypto.getRandomValues(bytes);
        return bytes;
    }
    TypeCrypt.randomBytes = randomBytes;
    function toUtf8Bytes(plainText) {
        let enc = new TextEncoder();
        return enc.encode(plainText);
    }
    TypeCrypt.toUtf8Bytes = toUtf8Bytes;
    function fromUtf8Bytes(buffer) {
        let dec = new TextDecoder();
        return dec.decode(buffer);
    }
    TypeCrypt.fromUtf8Bytes = fromUtf8Bytes;
    function toBase64String(buffer) {
        let base64String = btoa(String.fromCharCode(...new Uint8Array(buffer)));
        return base64String;
    }
    TypeCrypt.toBase64String = toBase64String;
    function fromBase64String(base64String) {
        let buffer = Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
        return buffer;
    }
    TypeCrypt.fromBase64String = fromBase64String;
})(TypeCrypt || (TypeCrypt = {}));
