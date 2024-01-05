const inquirer = require('inquirer')
const colors = require('colors')
const bip39 = require("bip39")
const ecc = require('tiny-secp256k1');
const crypto = require('crypto');

const {BIP32Factory} = require("bip32");
const log = require('../configs/constants');
const createNewWallet = require('../db/createNewWallet');

class Set {
    generate = async ()=>{
        /* const initialDerivationPath = "m/44'/0'/0'/0";
        const bip32 = BIP32Factory(ecc); */
        
        log("This is your mnemonic, save in a safe place: ")
        const mnemonic = bip39.generateMnemonic(128)
        log(mnemonic)
        //const seedBuffer = bip39.mnemonicToSeedSync(mnemonic)

        
        const newUser = await inquirer.prompt([
            {
                type: 'confirm',
                name: 'confirm',
                message: 'Have you saved your mnemonic in a safe place? ==> '.cyan,
            },
            {
                type: 'password',
                name: 'password',
                message: 'Create your password para utilizar por defecto este mnemonic (use minimum 6 digits):'
            },
            {
                type: 'password',
                name: 'confirmPassword',
                message: 'Repeat your new password para encriptar este mnemonic:'
            }
        ])

        if(newUser.confirm === false) {
            log("Make sure to save the mnemonic before continuing to use the wallet")
            return
        }

        if(newUser.password.length < 6){
            log("Password too short, try again with password of 6 digits or more")
            return
        }

        if(newUser.password !== newUser.confirmPassword){
            log("Passwords do not match, try again with identical passwords")
            return
        }
        const iv = crypto.randomBytes(16); // Deberías almacenar el IV utilizado durante el cifrado, es necesario para el descifrado

        // Derivar una clave de cifrado utilizando la contraseña
        const cipherKey = crypto.createHash('sha256').update(newUser.password).digest();
        
        // Crear el cifrador utilizando createCipheriv
        const cipher = crypto.createCipheriv('aes-256-cbc', cipherKey, iv);

        // Cifrar el texto
        let encryptedMnemonic = cipher.update(mnemonic, 'utf8', 'hex');
        encryptedMnemonic += cipher.final('hex');

        log("Your encrypted mnemonic is " + encryptedMnemonic)
        await createNewWallet(encryptedMnemonic,iv, newUser.password, )
    }

}

module.exports = Set