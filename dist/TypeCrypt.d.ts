declare namespace TypeCrypt {
    function newSigningKeyPair(): Promise<[PrivateSigningKey, PublicSigningKey]>;
    class PrivateSigningKey {
        key: CryptoKey;
        constructor(key: CryptoKey);
        export(): Promise<ArrayBuffer>;
        static import(encodedString: string): Promise<PrivateSigningKey>;
        sign(data: ArrayBuffer): Promise<ArrayBuffer>;
    }
    class PublicSigningKey {
        key: CryptoKey;
        constructor(key: CryptoKey);
        export(): Promise<ArrayBuffer>;
        static import(encodedString: string): Promise<PublicSigningKey>;
        verify(data: ArrayBuffer, signature: ArrayBuffer): Promise<boolean>;
    }
    function newAESKey(passphrase: ArrayBuffer): Promise<AESKey>;
    function getAESKey(passphrase: ArrayBuffer, salt: Uint8Array): Promise<AESKey>;
    class AESKey {
        salt: Uint8Array;
        key: CryptoKey;
        constructor(salt: Uint8Array, key: CryptoKey);
        encrypt(data: ArrayBuffer): Promise<AESCrypted>;
        decrypt(data: AESCrypted): Promise<ArrayBuffer>;
    }
    class AESCrypted {
        iv: Uint8Array;
        cipherText: ArrayBuffer;
        constructor(iv: Uint8Array, cipherText: ArrayBuffer);
        toString(): string;
        static fromString(encryptedString: string): AESCrypted;
    }
    function newEncryptionKeyPair(): Promise<[PrivateEncryptionKey, PublicEncryptionKey]>;
    class PrivateEncryptionKey {
        key: CryptoKey;
        constructor(key: CryptoKey);
        export(): Promise<ArrayBuffer>;
        static import(encodedString: string): Promise<PrivateEncryptionKey>;
    }
    class PublicEncryptionKey {
        key: CryptoKey;
        constructor(key: CryptoKey);
        export(): Promise<ArrayBuffer>;
        static import(encodedString: string): Promise<PublicEncryptionKey>;
    }
    function deriveSharedKey(privateKey: PrivateEncryptionKey, publicKey: PublicEncryptionKey): Promise<AESKey>;
    function randomBytes(numOfBytes: number): Uint8Array;
    function toUtf8Bytes(plainText: string): Uint8Array;
    function fromUtf8Bytes(buffer: ArrayBuffer): string;
    function toBase64String(buffer: ArrayBuffer): string;
    function fromBase64String(base64String: string): Uint8Array;
}
