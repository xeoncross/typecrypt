"use strict";
/// <reference path="../src/TypeCrypt.ts" />
let expect = chai.expect;
describe('TypeCrypt', () => {
    describe('#newAESKey()', () => {
        it('A key can be recreated with same passphrase & salt', async () => {
            let plainText = 'some text';
            let passphrase = TypeCrypt.toUtf8Bytes('a passphrase');
            let AESKey = await TypeCrypt.newAESKey(passphrase);
            let cipherText = await AESKey.encrypt(TypeCrypt.toUtf8Bytes(plainText));
            let AESKey2 = await TypeCrypt.getAESKey(passphrase, AESKey.salt);
            let decipheredText = await AESKey.decrypt(cipherText);
            expect(TypeCrypt.fromUtf8Bytes(decipheredText)).to.deep.equal(plainText);
        });
    });
    describe('encrypt json', () => {
        it('should encrypt and decrypt a JSON object', async () => {
            let passphrase = TypeCrypt.toUtf8Bytes('a passphrase');
            let data = { id: 1234, name: "john" };
            let plainText = TypeCrypt.toUtf8Bytes(JSON.stringify(data));
            let AESKey = await TypeCrypt.newAESKey(passphrase);
            let encrypted = await AESKey.encrypt(plainText);
            let decrypted = await AESKey.decrypt(encrypted);
            let decoded = TypeCrypt.fromUtf8Bytes(decrypted);
            let result = JSON.parse(decoded);
            expect(result).to.deep.equal(data);
        });
    });
    describe('#sign()', () => {
        it('a signature can be validated', async () => {
            let message = TypeCrypt.toUtf8Bytes('some text');
            let [priKey, pubKey] = await TypeCrypt.newSigningKeyPair();
            let signature = await priKey.sign(message);
            let valid = await pubKey.verify(message, signature);
            expect(valid).to.be.true;
            signature = new ArrayBuffer(signature.byteLength);
            valid = await pubKey.verify(message, signature);
            expect(valid).to.be.false;
        });
    });
    describe('key exchange', () => {
        it('should transmit message between two key pairs', async () => {
            // let passphrase1 = 'a passphrase'
            // let passphrase2 = 'another passphrase'
            // Alice and Bob want to talk
            // They generate their key pairs and each fetch a copy of the others public key
            let [alicePriKey, alicePubKey] = await TypeCrypt.newEncryptionKeyPair();
            let [bobPriKey, bobPubKey] = await TypeCrypt.newEncryptionKeyPair();
            // Alice then generates a secret key using her private key and Bob's public key.
            let aliceSecretKey = await TypeCrypt.deriveSharedKey(alicePriKey, bobPubKey);
            // Bob generates the same secret key using his private key and Alice's public key.
            let bobSecretKey = await TypeCrypt.deriveSharedKey(bobPriKey, alicePubKey);
            // Alice can then use her copy of the secret key to encrypt a message to Bob.
            let plainText = "hello Bob!";
            let cipherText = await aliceSecretKey.encrypt(TypeCrypt.toUtf8Bytes(plainText));
            // Bob can use his copy to decrypt the message.
            let buffer = await bobSecretKey.decrypt(cipherText);
            let decipheredText = TypeCrypt.fromUtf8Bytes(buffer);
            expect(decipheredText).to.equal(plainText);
        });
    });
    // Modeling a social network without robust forward secrecy
    describe('possible signup process', () => {
        it('should create and secure a new account', async () => {
            // Each account has the primary identity keypair that is used to 
            // direct people to the correct, current keypair to use for messaging.
            // This is done by signing the correct account bundle to prove that 
            // is what should be used to contact them.
            //
            // 1) Eventually, this will provide a way to recover an account when the accountKeypair is 
            //    encrypted with a different passphrase which is stored with friends / printed out
            // 2) as well as givethe account owner the option to change encryption keys as needed
            // without losing their public key identity.
            let accountPassphrase = TypeCrypt.randomBytes(32);
            let accountLock = await TypeCrypt.newAESKey(accountPassphrase);
            let [accountPriKey, accountPubKey] = await TypeCrypt.newSigningKeyPair();
            // The identity for the user is:
            let id = await accountPubKey.export();
            // User password used to encrypt and secure the account identity (at first) as well as each keypair used
            let userPassphrase = TypeCrypt.toUtf8Bytes("password1");
            let userLock = await TypeCrypt.newAESKey(userPassphrase);
            // Each account has two (replace-able) keypairs that are used for public and private messages
            // These keypairs are replaced every X duration with new ones
            // For private messages (signing not needed)
            let [userEncryptionPriKey, userEncryptionPubKey] = await TypeCrypt.newEncryptionKeyPair();
            // For public messages (encryption not needed)
            let [userSigningPriKey, userSigningPubKey] = await TypeCrypt.newSigningKeyPair();
            let mostRecentKey = {
                created: Date.now(),
                encryption: {
                    pubic: await userEncryptionPubKey.export(),
                    private: (await userLock.encrypt(await userEncryptionPriKey.export())).toString()
                },
                signing: {
                    pubic: await userSigningPubKey.export(),
                    private: (await userLock.encrypt(await userSigningPriKey.export())).toString()
                },
            };
            // Identity verification, proving these are the correct keys to use
            // Use the identity (accountPubKey) to verify this signature
            let mostRecentKeySignature = accountPriKey.sign(TypeCrypt.toUtf8Bytes(JSON.stringify(mostRecentKey)));
            // Client Needs:
            // 1) public requesting data for this user
            //  - profile (username, bio, image, etc...)
            //  - public keys
            //  - friend list(?)
            //  - messages by user
            // 2) user logging on fetching all their account data
            // Multiple generations of keypairs allow us basic forward secrecy
            // and the abillity to recover an identity should the account password be 
            // compromised by allowing us to issue new keys for this identity
            // PATH: /[identity]/keys/[latest|all]
            let keys = [
                [mostRecentKey, mostRecentKeySignature]
                // additional past keys
                // [ ... ], 
                // [ ... ],
            ];
            // 
            // Notes:
            //
            // - Most everything needs to be signed: accountPriKey.sign(...) to prevent modification
            // - All messages this user sends need to have the "created" date appended
            //   so the receiver knows which version of this identity to use...?
            //   [accountPubKey : 1234567890]
            // Only pulled when changing account key pairs (lost password, etc..)
            // Stored using the publicKey as the key
            let identityRecord = {
                // created: no, we don't let the creator say how old his account is
                salt: accountLock.salt,
                privateKey: (await accountLock.encrypt(await accountPriKey.export())).toString(),
            };
            // We can created shared secrets by fetching the public key of someone we want to talk with
            // Instead of doing a HTTP request for it, lets make a pretend friend here
            let [_, friendsPubKey] = await TypeCrypt.newEncryptionKeyPair();
            let sharedSecretKey = await TypeCrypt.deriveSharedKey(userEncryptionPriKey, friendsPubKey);
            // User metadata and account storage 
            let profile = {
                // Anyone can see this data
                public: {
                    username: "john",
                    photo: "?",
                    bio: "website or other description?",
                    recommended: ["identity1", "identity2"],
                },
                private: {
                    friends: [
                        // This is their account identity public key. Every time we want to message them 
                        // we download their most recent key and derive a shared secret (shown above).
                        // On login, we also fetch their profile and keep it in memory for the session
                        // This means profile changes can take a bit to refresh if the owner changes them.
                        "identity1",
                        "identity2",
                    ],
                    groups: [
                    // Need to store private keys here for groups we moderate
                    ],
                    topics: [
                    // list of topics this user wants to see the latest posts from in his feed
                    ]
                }
            };
            // All of these represent the user
            let x = {
                identity: identityRecord,
                keys,
                public: profile.public,
                provate: profile.private,
            };
        });
    });
});
