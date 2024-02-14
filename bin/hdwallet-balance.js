const colors = require('colors')
const inquirer = require('inquirer')
const ecashaddr = require('ecashaddrjs')
const { ChronikClient } = require('chronik-client');
const getConnection = require("../db/getConnection.js");
const { log } = require('../configs/constants.js')

const { chronikInstance } = require("../configs/constants.js")

async function hdwalletBalance() {
    const db = await getConnection("addresses")
    const chronik = new ChronikClient(chronikInstance);

    const aliasAndAddress =[]  

    for(let i = 0; i < db.data.addresses.length; i++){
        aliasAndAddress[i] = db.data.addresses[i].index + " " + db.data.addresses[i].alias +" "+db.data.addresses[i].ecashAddress
    }

    const options = [
        {
            name: "address",
            type: "list",
            message: "Select one wallet: ",
            choices: aliasAndAddress
        }
    ]
    
    const result = await inquirer.prompt(options)
    const aliasAndAddressSelected = result.address.split(" ")
    const eCashAddress = String(aliasAndAddressSelected[aliasAndAddressSelected.length-1])
    log("eCashAddress", eCashAddress)
    const { type, hash } = ecashaddr.decode(eCashAddress, true); 
    const utxos = await chronik.script(type, hash).utxos();
    const propertyToSum = 'value';
    if(utxos[0] !== undefined){
        const sum = utxos[0].utxos.reduce((accumulator, object) => accumulator + (object[propertyToSum]/100), 0);
        log("balance:")
        log(sum ,"XEC")
    }else{
        log("Your balance in this wallet is 0 XEC")
    }
}

hdwalletBalance()