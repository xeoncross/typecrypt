namespace TypeCrypt {

    const PBKDF2_ITERATIONS = 100_000

    // TODO: unique key class for each type which can stringify/unstringify itself using
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey

    // TODO: Fails to satisfy typescript constraints for some reason
    // https://developer.mozilla.org/en-US/docs/Web/API/EcKeyGenParams
    // const ecdsaParams: EcKeyGenParams = {
    //     name: "ECDSA",
    //     namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
    // }

    export async function newSigningKeyPair(): Promise<[PrivateSigningKey, PublicSigningKey]> {
        let key = await window.crypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
            },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["sign", "verify"]
        )
        
        return [new PrivateSigningKey(key.privateKey), new PublicSigningKey(key.publicKey)]
    }

    // Used to sign
    export class PrivateSigningKey {
        constructor(
            public key: CryptoKey
        ) {
        }

        // DANGER! Must be wrapped!
        public async export(): Promise<ArrayBuffer> {
            return await crypto.subtle.exportKey("raw", this.key)
            // let ab = await crypto.subtle.exportKey("raw", this.key)
            // return toBase64String(ab)
        }

        static async import(encodedString: string): Promise<PrivateSigningKey> {
            let ab = fromBase64String(encodedString)

            let key = await crypto.subtle.importKey(
                "raw", 
                ab, 
                {
                    name: "ECDSA",
                    namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
                },
                true, //whether the key is extractable (i.e. can be used in exportKey)
                ["sign"]
            )

            return new PrivateSigningKey(key)
        }

        public async sign(data: ArrayBuffer): Promise<ArrayBuffer> {
            return await crypto.subtle.sign(
                {
                    name: "ECDSA",
                    hash: {name: "SHA-256"},
                },
                this.key,
                data
            )
        }
    }

    // Used to verify identify
    export class PublicSigningKey {
        constructor(
            public key: CryptoKey
        ) {
        }

        public async export(): Promise<ArrayBuffer> {
            return await crypto.subtle.exportKey("raw", this.key)
            // let ab = await crypto.subtle.exportKey("raw", this.key)
            // return toBase64String(ab)
        }

        static async import(encodedString: string): Promise<PublicSigningKey> {
            let ab = fromBase64String(encodedString)

            let key = await crypto.subtle.importKey(
                "raw", 
                ab, 
                {
                    name: "ECDSA",
                    namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
                },
                true, //whether the key is extractable (i.e. can be used in exportKey)
                ["verify"]
            )

            return new PublicSigningKey(key)
        }

        public async verify(data: ArrayBuffer, signature: ArrayBuffer): Promise<boolean> {
            return crypto.subtle.verify(
                {
                    name: "ECDSA",
                    hash: {name: "SHA-256"},
                },
                this.key,
                signature,
                data,
            )
        }
    }

    //
    // AES Keys
    //
    // Used for wrapping signing and encryption keypairs

    export async function newAESKey(passphrase: ArrayBuffer): Promise<AESKey> {
        let salt = randomBytes(32)
        return getAESKey(passphrase, salt)
    }

    export async function getAESKey(passphrase: ArrayBuffer, salt: Uint8Array): Promise<AESKey> {
        let keyMaterial = await getKeyMaterial(passphrase)

        let key = await window.crypto.subtle.deriveKey(
            {
                "name": "PBKDF2",
                salt: salt,
                "iterations": PBKDF2_ITERATIONS,
                "hash": "SHA-256"
            },
            keyMaterial,
            { "name": "AES-GCM", "length": 256 },
            true,
            ["encrypt", "decrypt"]
        )

        return new AESKey(salt, key)
    }

    // AESKeys are always generated, never exported/stored
    export class AESKey {
        constructor(
            public salt: Uint8Array,
            public key: CryptoKey
        ) { }

        public async encrypt(data: ArrayBuffer): Promise<AESCrypted> {
            let iv = randomBytes(32)

            let cipherText = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv
                },
                this.key,
                data
            )
            return new AESCrypted(iv, cipherText)
        }

        public async decrypt(data: AESCrypted): Promise<ArrayBuffer> {
            let { iv, cipherText } = data

            return await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv
                },
                this.key,
                cipherText
            )
        }
    }


    export class AESCrypted {
        constructor(
            public iv: Uint8Array,
            public cipherText: ArrayBuffer,
        ) { }

        toString(): string {
            return `${toBase64String(this.iv)}:${toBase64String(this.cipherText)}`
        }

        static fromString(encryptedString: string): AESCrypted {
            let parts = encryptedString.split(':')
            let [iv, cipherText] = parts.map(fromBase64String)
            return new AESCrypted(iv, cipherText)
        }
    }


    //
    // EC Encryption Keys
    //


    export async function newEncryptionKeyPair(): Promise<[PrivateEncryptionKey, PublicEncryptionKey]> {
        let key = await window.crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-521", //can be "P-256", "P-384", or "P-521"
            },
            true,
            ["deriveKey"]
        );
        
        return [new PrivateEncryptionKey(key.privateKey), new PublicEncryptionKey(key.publicKey)]
    }

    export class PrivateEncryptionKey {
        constructor(
            public key: CryptoKey
        ) {
        }

        // DANGER! Must be encrypted!
        public async export(): Promise<ArrayBuffer> {
            return await crypto.subtle.exportKey("raw", this.key)
            // let ab = await crypto.subtle.exportKey("raw", this.key)
            // return toBase64String(ab)
        }

        static async import(encodedString: string): Promise<PrivateEncryptionKey> {
            let ab = fromBase64String(encodedString)

            let key = await crypto.subtle.importKey(
                "raw", 
                ab, 
                {
                    name: "ECDH",
                    namedCurve: "P-521",
                },
                true, //whether the key is extractable (i.e. can be used in exportKey)
                ["deriveKey"]
            )

            return new PrivateEncryptionKey(key)
        }
    }

    export class PublicEncryptionKey {
        constructor(
            public key: CryptoKey
        ) {
        }

        public async export(): Promise<ArrayBuffer> {
            return await crypto.subtle.exportKey("raw", this.key)
            // let ab = await crypto.subtle.exportKey("raw", this.key)
            // return toBase64String(ab)
        }

        static async import(encodedString: string): Promise<PublicEncryptionKey> {
            let ab = fromBase64String(encodedString)

            let key = await crypto.subtle.importKey(
                "raw", 
                ab, 
                {
                    name: "ECDSA",
                    namedCurve: "P-521",
                },
                true, //whether the key is extractable (i.e. can be used in exportKey)
                ["deriveKey"]
            )

            return new PublicEncryptionKey(key)
        }
    }

    // TODO need to be able to export and save both parts of this?
    export async function deriveSharedKey(privateKey: PrivateEncryptionKey, publicKey: PublicEncryptionKey) {
        let key = await window.crypto.subtle.deriveKey(
            {
                name: "ECDH",
                public: publicKey.key
            },
            privateKey.key,
            {
                name: "AES-GCM",
                length: 256
            },
            false, // Shared key is created when needed, but never stored
            ["encrypt", "decrypt"]
        );

        return new AESKey(new Uint8Array(), key)
    }

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


    async function getKeyMaterial(passphrase: ArrayBuffer): Promise<CryptoKey> {
        let keyMaterial = window.crypto.subtle.importKey(
            "raw",
            passphrase,
            { name: "PBKDF2" } as any,  // TODO: fix this in typescript definition
            false,
            ["deriveBits", "deriveKey"]
        )
        return keyMaterial
    }

    export function randomBytes(numOfBytes: number): Uint8Array {
        let bytes = new Uint8Array(numOfBytes)
        window.crypto.getRandomValues(bytes)
        return bytes
    }

    export function toUtf8Bytes(plainText: string): Uint8Array {
        let enc = new TextEncoder()
        return enc.encode(plainText)
    }

    export function fromUtf8Bytes(buffer: ArrayBuffer): string {
        let dec = new TextDecoder()
        return dec.decode(buffer)
    }

    export function toBase64String(buffer: ArrayBuffer): string {
        let base64String = btoa(String.fromCharCode(...new Uint8Array(buffer)));
        return base64String
    }

    export function fromBase64String(base64String: string): Uint8Array {
        let buffer = Uint8Array.from(atob(base64String), c => c.charCodeAt(0))
        return buffer
    }
}
