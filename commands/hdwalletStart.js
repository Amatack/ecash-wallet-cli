const inquirer = require('inquirer')
const colors = require('colors')
const bip39 = require("bip39")
const ecc = require('tiny-secp256k1');
const crypto = require('crypto');
const utxolib = require('@bitgo/utxo-lib')
const ecashaddrjs = require("ecashaddrjs");

const {BIP32Factory} = require("bip32");
const {log, derivationPath} = require('../configs/constants');
const getConnection = require('../db/getConnection');

class Set {
    generate = async ()=>{
        const {fromString} = await import('uint8arrays');
        
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

        const dbAccount = await getConnection("account")

        if(dbAccount.data.account.length > 0) {
            log("Do you want to change your current mnemonic for another?")
            return
        }
        console.log("Create new wallet ")

        const bip32 = BIP32Factory(ecc);
        const seedBuffer = bip39.mnemonicToSeedSync(mnemonic)

        const hdNode = utxolib.bip32.fromSeed(seedBuffer);
        const derivedNode = hdNode.derivePath("m/44'/0'/0'/0");

        //const masterKey = bip32.fromSeed(seedBuffer)
        const xPub = derivedNode.neutered().toBase58();

        await dbAccount.update(({ account }) => account.push({mnemonic: encryptedMnemonic, iv, xPub}))

        //Almacenar la primera dirección

        // Utilizar la misma clave y IV que se usaron para cifrar
        const cipherKey2 = crypto.createHash('sha256').update(newUser.password).digest();
        // Crear el descifrador utilizando createDecipheriv
        const decipher = crypto.createDecipheriv('aes-256-cbc', cipherKey2, iv);
        // Descifrar el texto
        let decryptedMnemonic = decipher.update(encryptedMnemonic, 'hex', 'utf8');
        decryptedMnemonic += decipher.final('utf8');

        console.log("Your decrypted mnemonic is " + decryptedMnemonic);

        const masterKey = bip32.fromSeed(seedBuffer)
        const initialDerivationPath = derivationPath
        const publicKey = masterKey.derivePath(initialDerivationPath)
        
        const legacyAddress = utxolib.payments.p2pkh({ pubkey: publicKey.derive(0).publicKey }).address;
        const hash = utxolib.address.fromBase58Check(legacyAddress).hash.toString('hex')
        //log("uint8arrays: ",uint8arrays)
        const uint8array = fromString(hash, 'hex')
        const ecashAddress = ecashaddrjs.encode("ecash", "P2PKH" , uint8array)
        console.log('Dirección 0:', ecashAddress);

        const dbAddresses = await getConnection("addresses")
        
        await dbAddresses.update(({ addresses }) => addresses.push({index: 0,ecashAddress:ecashAddress}))
        console.log("Db created successfully")
    }
}

module.exports = Set