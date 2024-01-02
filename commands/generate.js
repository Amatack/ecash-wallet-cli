const inquirer = require('inquirer')
const colors = require('colors')
const bip39 = require("bip39")
const ecc = require('tiny-secp256k1');

const {BIP32Factory} = require("bip32")

class Set {
    generate = async ()=>{
        const initialDerivationPath = "m/44'/0'/0'/0";
        const bip32 = BIP32Factory(ecc);
        console.log("This is your mnemonic, save in a safe place: ")
        const mnemonic = bip39.generateMnemonic(128)
        const seedBuffer = bip39.mnemonicToSeedSync(mnemonic, "contraseña")
        bip39.mnemonicToEntropy()
        const seedBuffer2 = bip39.mnemonicToSeedSync(mnemonic)
        console.log("seedString2: ", seedString2)
        const newUser = await inquirer.prompt([
            {
                type: 'confirm',
                name: 'confirm',
                message: 'Have you saved your mnemonic in a safe place? ==> '.cyan,
            },
            {
                type: 'password',
                name: 'password',
                message: 'Create your password para utilizar por defecto este mnemonic:'
            },
            {
                type: 'password',
                name: 'confirmPassword',
                message: 'Repeat your new password para encriptar este mnemonic:'
            }
        ])
        
        console.log(newUser)
    }
    removePlayer = async ()=>{
        console.log(playerData.length)
        playerData.forEach( (value, index)=>console.log(index, value))

        const indexNum = await inquirer.prompt([
            {
                type: 'number',
                name: 'player',
                message: 'Enter the index number which you want to remove from player set ==> '.cyan 
            }
        ])
        
        playerData.splice(indexNum.player, 1)
        playerData.forEach( (value, index)=>console.log(index, value))
        console.log("Remove player ")
    }

}

module.exports = Set