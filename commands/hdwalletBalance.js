const inquirer = require('inquirer')
const ecashaddr = require('ecashaddrjs')
const { ChronikClient } = require('chronik-client');
const getConnection = require("../db/getConnection.js");
const { log } = require('../configs/constants.js')

const { chronikInstance } = require("../configs/constants.js");
const { program } = require('commander');
class Set {
    balance = async ()=>{
        if(program.rawArgs[2] === "-a" || program.rawArgs[2] === "--allAddresses" || program.rawArgs[3] === "-a" || program.rawArgs[3] === "--allAddresses"){
            try{
                const db = await getConnection("addresses")
                const chronik = new ChronikClient(chronikInstance);
                let totalBalance = 0
                for(let i = 0; i < db.data.addresses.length; i++){
                    
                    const eCashAddress = db.data.addresses[i].ecashAddress
                    
                    const { type, hash } = ecashaddr.decode(eCashAddress, true); 
                    const utxos = await chronik.script(type, hash).utxos();
                    const propertyToSum = 'value';
                    if(utxos[0] !== undefined){
                        const sum = utxos[0].utxos.reduce((accumulator, object) => accumulator + (object[propertyToSum]/100), 0);
                        
                        totalBalance = totalBalance + sum
                    }
                }

                log("balance:")
                log(totalBalance ,"XEC")
                
                
                
            }catch{(err)=>log(err)}
            return
        }

        
        const db = await getConnection("addresses")
        
        const chronik = new ChronikClient(chronikInstance);

        const indexAndAddress =[]  

        for(let i = 0; i < db.data.addresses.length; i++){
            indexAndAddress[i] = db.data.addresses[i].index + " " +db.data.addresses[i].ecashAddress
        }

        const options = [
            {
                name: "address",
                type: "list",
                message: "Select one wallet: ",
                choices: indexAndAddress
            }
        ]
        
        const result = await inquirer.prompt(options)
        const indexAndAddressSelected = result.address.split(" ")
        const eCashAddress = String(indexAndAddressSelected[indexAndAddressSelected.length-1])
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

}
module.exports = Set