const bitcoinjs = require('bitcoinjs-lib');
const {encode} = require('ecashaddrjs')
const { Buffer } = require('buffer')

async function getAddressFromOutputScript(script){
    const {fromString} = await import('uint8arrays');
    const bufer = Buffer.from(script, 'hex' )
    const legacyAddress = bitcoinjs.address.fromOutputScript(bufer)
    const hash = bitcoinjs.address.fromBase58Check(legacyAddress).hash.toString('hex')
    const uint8array = fromString(hash, 'hex')
    return encode("ecash", "P2PKH" , uint8array)
}

module.exports = getAddressFromOutputScript