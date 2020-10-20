"use strict";
var TypeCrypt;
(function (TypeCrypt) {
    const PBKDF2_ITERATIONS = 100000;
    // TODO: unique key class for each type which can stringify/unstringify itself using
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
    // TODO: Fails to satisfy typescript constraints for some reason
    // https://developer.mozilla.org/en-US/docs/Web/API/EcKeyGenParams
    // const ecdsaParams: EcKeyGenParams = {
    //     name: "ECDSA",
    //     namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
    // }
    async function newSigningKeyPair() {
        let key = await window.crypto.subtle.generateKey({
            name: "ECDSA",
            namedCurve: "P-521",
        }, true, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign", "verify"]);
        return [new PrivateSigningKey(key.privateKey), new PublicSigningKey(key.publicKey)];
    }
    TypeCrypt.newSigningKeyPair = newSigningKeyPair;
    // Used to sign
    class PrivateSigningKey {
        constructor(key) {
            this.key = key;
        }
        // DANGER! Must be wrapped!
        async export() {
            return await crypto.subtle.exportKey("raw", this.key);
            // let ab = await crypto.subtle.exportKey("raw", this.key)
            // return toBase64String(ab)
        }
        static async import(encodedString) {
            let ab = fromBase64String(encodedString);
            let key = await crypto.subtle.importKey("raw", ab, {
                name: "ECDSA",
                namedCurve: "P-521",
            }, true, //whether the key is extractable (i.e. can be used in exportKey)
            ["sign"]);
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
    // Used to verify identify
    class PublicSigningKey {
        constructor(key) {
            this.key = key;
        }
        async export() {
            return await crypto.subtle.exportKey("raw", this.key);
            // let ab = await crypto.subtle.exportKey("raw", this.key)
            // return toBase64String(ab)
        }
        static async import(encodedString) {
            let ab = fromBase64String(encodedString);
            let key = await crypto.subtle.importKey("raw", ab, {
                name: "ECDSA",
                namedCurve: "P-521",
            }, true, //whether the key is extractable (i.e. can be used in exportKey)
            ["verify"]);
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
    //
    // AES Keys
    //
    // Used for wrapping signing and encryption keypairs
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
    // AESKeys are always generated, never exported/stored
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
    //
    // EC Encryption Keys
    //
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
        // DANGER! Must be encrypted!
        async export() {
            return await crypto.subtle.exportKey("raw", this.key);
            // let ab = await crypto.subtle.exportKey("raw", this.key)
            // return toBase64String(ab)
        }
        static async import(encodedString) {
            let ab = fromBase64String(encodedString);
            let key = await crypto.subtle.importKey("raw", ab, {
                name: "ECDH",
                namedCurve: "P-521",
            }, true, //whether the key is extractable (i.e. can be used in exportKey)
            ["deriveKey"]);
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
            // let ab = await crypto.subtle.exportKey("raw", this.key)
            // return toBase64String(ab)
        }
        static async import(encodedString) {
            let ab = fromBase64String(encodedString);
            let key = await crypto.subtle.importKey("raw", ab, {
                name: "ECDSA",
                namedCurve: "P-521",
            }, true, //whether the key is extractable (i.e. can be used in exportKey)
            ["deriveKey"]);
            return new PublicEncryptionKey(key);
        }
    }
    TypeCrypt.PublicEncryptionKey = PublicEncryptionKey;
    // TODO need to be able to export and save both parts of this?
    async function deriveSharedKey(privateKey, publicKey) {
        let key = await window.crypto.subtle.deriveKey({
            name: "ECDH",
            public: publicKey.key
        }, privateKey.key, {
            name: "AES-GCM",
            length: 256
        }, false, // Shared key is created when needed, but never stored
        ["encrypt", "decrypt"]);
        return new AESKey(new Uint8Array(), key);
    }
    TypeCrypt.deriveSharedKey = deriveSharedKey;
    // export class SharedSecretKey {
    //     constructor(
    //         public keypair: CryptoKeyPair
    //     ) {}
    // }
    // export async function encryptObject<T, K extends keyof T>(obj: T, props: Array<K>, key: CryptoKey): Promise<EncryptedObject<T, K>> {
    //     let encryptedObject = {} as any
    //     let encryptedProperties = {} as any
    //     for (let prop of Object.keys(obj)) {
    //         if (props.indexOf(prop as any) >= 0) {
    //             encryptedProperties[prop] = (obj as any)[prop]
    //         }
    //         else {
    //             encryptedObject[prop] = (obj as any)[prop]
    //         }
    //     }
    //     encryptedObject.encrypted = await encrypt(JSON.stringify(encryptedProperties), key)
    //     return encryptedObject
    // }
    // export async function newEncryptionKey(passphrase: string): Promise<LeanKey> {
    //     let salt = randomBytes(32)
    //     return getEncryptionKey(passphrase, salt)
    // }
    /*
    Derive an AES key, given:
    - our ECDH private key
    - their ECDH public key
    @https://mdn.github.io/dom-examples/web-crypto/derive-key/ecdh.js
    */
    // export async function deriveSecretKey(privateKey: CryptoKey, publicKey: CryptoKey) {
    //     return await window.crypto.subtle.deriveKey(
    //         {
    //             name: "ECDH",
    //             public: publicKey
    //         },
    //         privateKey,
    //         {
    //             name: "AES-GCM",
    //             length: 256
    //         },
    //         false,
    //         ["encrypt", "decrypt"]
    //     );
    // }
    // export async function newMessageKey(): Promise<CryptoKeyPair> {
    //     return await window.crypto.subtle.generateKey(
    //         {
    //             name: "ECDH",
    //             namedCurve: "P-384"
    //         },
    //         false,
    //         ["deriveKey"]
    //     );
    // }
    async function getKeyMaterial(passphrase) {
        let keyMaterial = window.crypto.subtle.importKey("raw", passphrase, { name: "PBKDF2" }, // TODO: fix this in typescript definition
        false, ["deriveBits", "deriveKey"]);
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
