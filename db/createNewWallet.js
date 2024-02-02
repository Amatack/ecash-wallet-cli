const bip39 = require("bip39");
const ecc = require('tiny-secp256k1');
const { BIP32Factory } = require('bip32');
const utxolib = require('@bitgo/utxo-lib');
const ecashaddrjs = require("ecashaddrjs");


const crypto = require('crypto');

const {log, derivationPath} = require('../configs/constants')

async function createNewWallet(encryptedMnemonic, iv, password) {
    try{
        const { JSONFilePreset } = await import('lowdb/node')
        const {fromString} = await import('uint8arrays');
        
        // Read or create db.json
        const defaultData = { account: [] }
        db = await JSONFilePreset('./data/account.json', defaultData)
        if(db.data.account.length !== 0) return
        console.log("Create new wallet ")
        await db.update(({ account }) => account.push({mnemonic: encryptedMnemonic, iv}))

        //Almacenar la primera dirección

        // Utilizar la misma clave y IV que se usaron para cifrar
        const cipherKey = crypto.createHash('sha256').update(password).digest();

        // Crear el descifrador utilizando createDecipheriv
        const decipher = crypto.createDecipheriv('aes-256-cbc', cipherKey, iv);

        // Descifrar el texto
        let decryptedMnemonic = decipher.update(encryptedMnemonic, 'hex', 'utf8');
        decryptedMnemonic += decipher.final('utf8');

        console.log("Your decrypted mnemonic is " + decryptedMnemonic);

        const bip32 = BIP32Factory(ecc);
        const seedBuffer = bip39.mnemonicToSeedSync(decryptedMnemonic)
        const masterKey = bip32.fromSeed(seedBuffer)
        const initialDerivationPath = derivationPath
        const publicKey = masterKey.derivePath(initialDerivationPath)
        const legacyAddress = utxolib.payments.p2pkh({ pubkey: publicKey.derive(0).publicKey }).address;

        const hash = utxolib.address.fromBase58Check(legacyAddress).hash.toString('hex')
        //log("uint8arrays: ",uint8arrays)
        const uint8array = fromString(hash, 'hex')
        const ecashAddress = ecashaddrjs.encode("ecash", "P2PKH" , uint8array)
        console.log('Dirección 0:', ecashAddress );

        const defaultData2 = { addresses: [] }
        db = await JSONFilePreset('./data/addresses.json', defaultData2)
        await db.update(({ addresses }) => addresses.push(ecashAddress))
        console.log("Db created successfully")
    } catch (error) {
        // Handle the error or initialize a new database if the file doesn't exist
        console.error('Error at initialize a new database:', error);
        return
    }
}

module.exports = createNewWallet;