const utxolib = require('@bitgo/utxo-lib')
const ecc = require('tiny-secp256k1');
const {BIP32Factory} = require("bip32");
const ecashaddrjs = require('ecashaddrjs')

const getConnection = require('../db/getConnection')
const {log} = require('../configs/constants');


class Set {
        add = async ()=>{
        
        const {fromString} = await import('uint8arrays');
        const dbAddresses = await getConnection("addresses")
        const NumberOfAddresses = dbAddresses.data.addresses.length

        const dbAccount = await getConnection("account")

        const bip32 = BIP32Factory(ecc);

        const masterKey = bip32.fromBase58(dbAccount.data.account[0].xPub)

        const legacyAddress = utxolib.payments.p2pkh({ pubkey: masterKey.derive(NumberOfAddresses).publicKey }).address;

        const hash = utxolib.address.fromBase58Check(legacyAddress).hash.toString('hex')
        const uint8array = fromString(hash, 'hex')

        const ecashAddress = ecashaddrjs.encode("ecash", "P2PKH" , uint8array)
            
        await dbAddresses.update(({ addresses }) => addresses.push({index: NumberOfAddresses, ecashAddress: ecashAddress}))
        log("new wallet added")
    }
}

module.exports = Set