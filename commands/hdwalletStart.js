const inquirer = require('inquirer')
const colors = require('colors')
const bip39 = require("bip39")
const ecc = require('tiny-secp256k1');
const crypto = require('crypto');
const fs = require('fs');
const utxolib = require('../modules/@bitgo/utxo-lib')
const ecashaddrjs = require("ecashaddrjs");

const {BIP32Factory} = require("bip32");
const {log, derivationPath} = require('../configs/constants');
const getConnection = require('../db/getConnection');

class Set {
    generate = async ()=>{
        const {fromString} = await import('uint8arrays');
        
        let mnemonicChange = {}
        //is fulfilled if user does not have an account in the database

        const filePath = './data/addresses.json';
        const filePath2 = './data/account.json';

        if (fs.existsSync(filePath2)) {
        

            mnemonicChange = await inquirer.prompt([
                {
                    type: 'confirm',
                    name: 'confirm',
                    message: 'Do you want to change your current mnemonic for another? ==> '.cyan,
                },
            ])

            if(mnemonicChange.confirm === false) return

            
            fs.unlinkSync(filePath);
            fs.unlinkSync(filePath2);
            
        } else {
            log('JSON file does not exist.');
        }
        

        const dbAccount = await getConnection("account")
        const dbAddresses = await getConnection("addresses")

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
                message: 'Create your password to decrypt this mnemonic (use minimum 6 digits):'
            },
            {
                type: 'password',
                name: 'confirmPassword',
                message: 'Repeat your new password para encrypt this mnemonic:'
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
        const iv = crypto.randomBytes(16); // You should store the IV used during encryption, it is necessary for decryption

        // Derive an encryption key using the password
        const cipherKey = crypto.createHash('sha256').update(newUser.password).digest();
        
        // Create the cipher using createCipheriv
        const cipher = crypto.createCipheriv('aes-256-cbc', cipherKey, iv);

        // Encrypt the text
        let encryptedMnemonic = cipher.update(mnemonic, 'utf8', 'hex');
        encryptedMnemonic += cipher.final('hex');

        //log("Your encrypted mnemonic is " + encryptedMnemonic)

        const bip32 = BIP32Factory(ecc);
        const seedBuffer = bip39.mnemonicToSeedSync(mnemonic)

        const hdNode = utxolib.bip32.fromSeed(seedBuffer);
        const derivedNode = hdNode.derivePath("m/44'/0'/0'/0");

        //const masterKey = bip32.fromSeed(seedBuffer)
        const xPub = derivedNode.neutered().toBase58();

        await dbAccount.update(({ account }) => account.push({mnemonic: encryptedMnemonic, iv, xPub}))
        
        //Save the first address

        const cipherKey2 = crypto.createHash('sha256').update(newUser.password).digest();
        const decipher = crypto.createDecipheriv('aes-256-cbc', cipherKey2, iv);
        let decryptedMnemonic = decipher.update(encryptedMnemonic, 'hex', 'utf8');
        decryptedMnemonic += decipher.final('utf8');

        //console.log("Your decrypted mnemonic is " + decryptedMnemonic);

        const masterKey = bip32.fromSeed(seedBuffer)
        const initialDerivationPath = derivationPath
        const publicKey = masterKey.derivePath(initialDerivationPath)
        
        const legacyAddress = utxolib.payments.p2pkh({ pubkey: publicKey.derive(0).publicKey }).address;
        const hash = utxolib.address.fromBase58Check(legacyAddress).hash.toString('hex')
        //log("uint8arrays: ",uint8arrays)
        const uint8array = fromString(hash, 'hex')
        const ecashAddress = ecashaddrjs.encode("ecash", "P2PKH" , uint8array)
        
        await dbAddresses.update(({ addresses }) => addresses.push({index: 0,ecashAddress:ecashAddress}))
        log("Success, new wallet created")
    };
    import = async ()=>{
        const {fromString} = await import('uint8arrays');
        
        let mnemonicChange = {}
        //is fulfilled if user does not have an account in the database

        const filePath = './data/addresses.json';
        const filePath2 = './data/account.json';

        if (fs.existsSync(filePath2)) {
        

            mnemonicChange = await inquirer.prompt([
                {
                    type: 'confirm',
                    name: 'confirm',
                    message: 'Do you want to change your current mnemonic for another? ==> '.cyan,
                },
            ])

            if(mnemonicChange.confirm === false) return

            
            fs.unlinkSync(filePath);
            fs.unlinkSync(filePath2);
            
        } else {
            log('JSON file does not exist.');
        }
        

        const dbAccount = await getConnection("account")
        const dbAddresses = await getConnection("addresses")

        //const seedBuffer = bip39.mnemonicToSeedSync(mnemonic)

        
        const newUser = await inquirer.prompt([
            {
                type: 'input',
                name: 'mnemonic',
                message: 'Write your mnemonic? ==> '.cyan,
            },
            {
                type: 'password',
                name: 'password',
                message: 'Create your password to decrypt this mnemonic (use minimum 6 digits):'
            },
            {
                type: 'password',
                name: 'confirmPassword',
                message: 'Repeat your new password para encrypt this mnemonic:'
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
        const iv = crypto.randomBytes(16); // You should store the IV used during encryption, it is necessary for decryption

        // Derive an encryption key using the password
        const cipherKey = crypto.createHash('sha256').update(newUser.password).digest();
        
        // Create the cipher using createCipheriv
        const cipher = crypto.createCipheriv('aes-256-cbc', cipherKey, iv);

        // Encrypt the text
        let encryptedMnemonic = cipher.update(newUser.mnemonic, 'utf8', 'hex');
        encryptedMnemonic += cipher.final('hex');

        //log("Your encrypted mnemonic is " + encryptedMnemonic)

        const bip32 = BIP32Factory(ecc);
        const seedBuffer = bip39.mnemonicToSeedSync(newUser.mnemonic)

        const hdNode = utxolib.bip32.fromSeed(seedBuffer);
        const derivedNode = hdNode.derivePath("m/44'/0'/0'/0");

        //const masterKey = bip32.fromSeed(seedBuffer)
        const xPub = derivedNode.neutered().toBase58();

        await dbAccount.update(({ account }) => account.push({mnemonic: encryptedMnemonic, iv, xPub}))
        
        //Save the first address

        const cipherKey2 = crypto.createHash('sha256').update(newUser.password).digest();
        const decipher = crypto.createDecipheriv('aes-256-cbc', cipherKey2, iv);
        let decryptedMnemonic = decipher.update(encryptedMnemonic, 'hex', 'utf8');
        decryptedMnemonic += decipher.final('utf8');

        //console.log("Your decrypted mnemonic is " + decryptedMnemonic);

        const masterKey = bip32.fromSeed(seedBuffer)
        const initialDerivationPath = derivationPath
        const publicKey = masterKey.derivePath(initialDerivationPath)
        
        const legacyAddress = utxolib.payments.p2pkh({ pubkey: publicKey.derive(0).publicKey }).address;
        const hash = utxolib.address.fromBase58Check(legacyAddress).hash.toString('hex')
        //log("uint8arrays: ",uint8arrays)
        const uint8array = fromString(hash, 'hex')
        const ecashAddress = ecashaddrjs.encode("ecash", "P2PKH" , uint8array)
        
        await dbAddresses.update(({ addresses }) => addresses.push({index: 0,ecashAddress:ecashAddress}))
        log("Success, new wallet created")
    };
}

module.exports = Set