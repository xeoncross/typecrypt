import { TypeCrypt } from '../dist/TypeCrypt.js'

window.addEventListener('load', function() {
    let leanCrypt = new TypeCrypt()

    document.getElementById('encrypt').addEventListener('click', async () => {
        let plainText = document.getElementById('plainText').value
        let password = document.getElementById('password').value

        let encrypted = await leanCrypt.encrypt(plainText, password)

        document.getElementById('cipherText').value = encrypted
    })

    document.getElementById('decrypt').addEventListener('click', async () => {
        let cipherText = document.getElementById('cipherText').value 
        let password = document.getElementById('password').value

        let decrypted = await leanCrypt.decrypt(cipherText, password)

        document.getElementById('plainText').value = decrypted
    })
})