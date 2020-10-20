/// <reference path="../src/TypeCrypt.ts" />

let expect = chai.expect

describe('TypeCrypt', () => {

    describe('#newAESKey()', () => {
        it('A key can be recreated with same passphrase & salt', async () => {
            let plainText = 'some text'
            let passphrase = TypeCrypt.toUtf8Bytes('a passphrase')

            let AESKey = await TypeCrypt.newAESKey(passphrase)

            let cipherText = await AESKey.encrypt(TypeCrypt.toUtf8Bytes(plainText))

            let AESKey2 = await TypeCrypt.getAESKey(passphrase, AESKey.salt)

            let decipheredText = await AESKey.decrypt(cipherText)

            expect(TypeCrypt.fromUtf8Bytes(decipheredText)).to.deep.equal(plainText)
        })
    })
    
    describe('encrypt json', () => {
        it('should encrypt and decrypt a JSON object', async () => {
            let passphrase = TypeCrypt.toUtf8Bytes('a passphrase')
            let data = {id: 1234, name:"john"}

            let plainText = TypeCrypt.toUtf8Bytes(JSON.stringify(data))

            let AESKey = await TypeCrypt.newAESKey(passphrase)

            let encrypted = await AESKey.encrypt(plainText)

            let decrypted = await AESKey.decrypt(encrypted)

            let decoded = TypeCrypt.fromUtf8Bytes(decrypted)

            let result = JSON.parse(decoded)

            expect(result).to.deep.equal(data)
        })
    })

    describe('#sign()', () => {
        it('a signature can be validated', async () => {
            let message = TypeCrypt.toUtf8Bytes('some text')

            let [priKey, pubKey] = await TypeCrypt.newSigningKeyPair()

            let signature = await priKey.sign(message)
            let valid = await pubKey.verify(message, signature)

            expect(valid).to.be.true

            signature = new ArrayBuffer(signature.byteLength)
            valid = await pubKey.verify(message, signature)

            expect(valid).to.be.false
        })
    })


    describe('key exchange', () => {
        it('should transmit message between two key pairs', async () => {
            // let passphrase1 = 'a passphrase'
            // let passphrase2 = 'another passphrase'

            // Alice and Bob want to talk

            // They generate their key pairs and each fetch a copy of the others public key
            let [alicePriKey, alicePubKey] = await TypeCrypt.newEncryptionKeyPair()
            let [bobPriKey, bobPubKey] = await TypeCrypt.newEncryptionKeyPair()

            // Alice then generates a secret key using her private key and Bob's public key.
            let aliceSecretKey = await TypeCrypt.deriveSharedKey(alicePriKey, bobPubKey);

            // Bob generates the same secret key using his private key and Alice's public key.
            let bobSecretKey = await TypeCrypt.deriveSharedKey(bobPriKey, alicePubKey);

            // Alice can then use her copy of the secret key to encrypt a message to Bob.
            let plainText = "hello Bob!"
            let cipherText = await aliceSecretKey.encrypt(TypeCrypt.toUtf8Bytes(plainText))

            // Bob can use his copy to decrypt the message.
            let buffer = await bobSecretKey.decrypt(cipherText)
            let decipheredText = TypeCrypt.fromUtf8Bytes(buffer)

            expect(decipheredText).to.equal(plainText)
        })
    })

    // https://mermaid-js.github.io/mermaid-live-editor/#/edit/
    describe('signup process', () => {
        it('should create and secure a new account', async () => {

            // Each account has the primary identity keypair that is used to 
            // direct people to the correct, current keypair to use for messaging.
            // This is done by signing the correct account bundle to prove that 
            // is what should be used to contact them.
            //
            // 1) This will provide a way to recover an account when the accountKeypair is 
            //    encrypted with a different passphrase which is stored with friends / printed out
            // 2) as well as givethe account owner the option to change encryption keys as needed
            // without losing their public key identity.

            let accountPassphrase = TypeCrypt.randomBytes(32)
            let accountLock = await TypeCrypt.newAESKey(accountPassphrase)
            let [accountPriKey, accountPubKey] = await TypeCrypt.newSigningKeyPair()

            // User password used to encrypt and secure the account identity (at first) as well as the keychain
            let userPassphrase = TypeCrypt.toUtf8Bytes("password1")
            let userLock = await TypeCrypt.newAESKey(userPassphrase)

            // Each account has two (replace-able) keypairs that are used for public and private messages

            // For private messages
            let [userEncryptionPriKey, userEncryptionPubKey] = await TypeCrypt.newEncryptionKeyPair()

            // For public messages
            let [userSigningPriKey, userSigningPubKey] = await TypeCrypt.newSigningKeyPair()

            // The identity for the user is:
            // id: await accountPubKey.export(),
            // This is the "key" -> value prefix used by the following account parts:

            // Everything needs to be signed: accountPriKey.sign(...)
            // All messages this user sends need to have the "created" date appended
            // so the reciever knows which version of this identity to use...?
            // [accountPubKey : 1234567890]


            // Only pulled when changing account key pairs (lost password, etc..)
            let identityRecord = {
                salt: accountLock.salt,
                privateKey: (await accountLock.encrypt(await accountPriKey.export())).toString(),
                // publicKey: accountPubKey.export(),
                // signature: accountPriKey.sign(TypeCrypt.toUtf8Bytes("^all this stuff above^"))
            }
            // Stored using the publicKey as the key
            // No need for a signature as only the person with the password (the account owner)
            // cares about the data in this (seldom accessed) record.

            // Needs:
            // 1) public requesting public keys for this user
            // 2) user logging on fetching all their account data

            // Key: /[identity]/keys/[latest|all] -> Value: JSON
            // v1/2/3/etc.. account record
            let keys = {
                created: Date.now(), // to know which key is newest
                encryptionKey: await userEncryptionPubKey.export(),
                signingKey: await userSigningPubKey.export(),
                // Identity verification, proving these are the correct keys to use
                // Use the identity (accountPubKey) to verify this signature
                signature: accountPriKey.sign(TypeCrypt.toUtf8Bytes("^all this stuff above^"))
            }
            
            // Key: /[identity]/account/[latest|all] -> Value: JSON
            // Encrypted, unreadable blob
            let account = {
                created: Date.now(), // matches keyRecord value
                salt: userLock.salt, // used to unlock
                data: { // encrypted!
                    encryptionKey: await userEncryptionPubKey.export(),
                    signingKey: await userSigningPubKey.export(),
                    following: ["pubkey1", "pubkey1", "etc..."],
                }
            }

            // // Step 2: Active keychain keys
            // // Messaging keypair
            // let randomPassphrase = TypeCrypt.fromUtf8Bytes(TypeCrypt.randomBytes(32))
            // let currentLockKeypair = await TypeCrypt.newEncryptionKey(randomPassphrase)


            // let accountKeypairJwk = await crypto.subtle.wrapKey("jwk", accountKeypair.Key, passphraseKeypair, "AES-GCM")

        })
    })

})