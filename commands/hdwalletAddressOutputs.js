const inquirer = require('inquirer')
const ecashaddr = require('ecashaddrjs')
const { ChronikClient } = require('chronik-client');
const getConnection = require("../db/getConnection.js");
const { log } = require('../configs/constants.js')
const getAddressFromOutputScript = require("../utils/getAddressFromOutputScript.js")

const { chronikInstance } = require("../configs/constants.js");
class Set {
    addressOuputs = async ()=>{
        
        const db = await getConnection("addresses")
        
        const chronik = new ChronikClient(chronikInstance);
        const indexAndAddress = ["write the address"]  

        for(let i = 0; i < db.data.addresses.length; i++){
            indexAndAddress[i+1] = db.data.addresses[i].index + " " +db.data.addresses[i].ecashAddress
        }

        const options = [
            {
                name: "address",
                type: "list",
                message: "Select one address: ",
                choices: indexAndAddress
            }
        ]
        
        const result = await inquirer.prompt(options)
        let eCashAddress = ""
        if(result.address === "write the address"){
            const options2 = [
                {
                    name: "address",
                    type: "text",
                    message: "Write address: ",
                }
            ]
            
            const result2 = await inquirer.prompt(options2)
            if(result2.address.length !== 48){
                log("You must enter an valid eCash address")
                return
            }

            eCashAddress = result2.address

        }else{
            const indexAndAddressSelected = result.address.split(" ")
            eCashAddress = String(indexAndAddressSelected[indexAndAddressSelected.length-1])
        }

        const { type, hash } = ecashaddr.decode(eCashAddress, true);

        const options3 = [
            {
                name: "tokenId",
                type: "text",
                message: "Write the tokenId(leave it empty for eCash outputs):",
                choices: indexAndAddress
            }
        ]
        
        const result3 = await inquirer.prompt(options3)

        const arrays = [];
        for(let n = 0;;n++){
            const addressHistory = await chronik.script(type, hash).history(n)
            if(addressHistory.txs.length === 0){
                break
            }else{
                //For eCash outputs
                if(result3.tokenId === ""){

                    for(let n2 = 0; n2 < addressHistory.txs.length; n2++){
                        
                        if(!addressHistory.txs[n2].slpTxData){
                            for(let n3= 0; n3 < addressHistory.txs[n2].outputs.length; n3++){
                                addressHistory.txs[n2].outputs[n3].time = addressHistory.txs[n2].block.timestamp
                                arrays.push(addressHistory.txs[n2].outputs[n3]);
                            }
                        }
                    }
                    
                }else{
                    //For eToken outputs
                    for(let n2 = 0; n2 < addressHistory.txs.length; n2++){
                        if(addressHistory.txs[n2].slpTxData){
                            if(addressHistory.txs[n2].slpTxData.slpMeta.tokenId === result3.tokenId) {
                                //log("addressHistory.txs[n2].outputs: ", addressHistory.txs[n2].outputs)
                                for(let n3= 0; n3 < addressHistory.txs[n2].outputs.length; n3++){
                                    if(addressHistory.txs[n2].outputs[n3].slpToken !== undefined){
                                        
                                        addressHistory.txs[n2].outputs[n3].time = addressHistory.txs[n2].block.timestamp
                                        arrays.push(addressHistory.txs[n2].outputs[n3]);
                                    }
                                }
                            }
                        }
                        
                    }
                }
            }
        }
        const totalOutputs = [].concat(...arrays);

        const totalOutputsFiltered = []
        

       

        for(let n4 = 0; n4 < totalOutputs.length ;n4++){

            let amount = ""
            
            if(result3.tokenId === ""){
                //For eCash outputs
                amount = totalOutputs[n4].value
            }else{
                //For eToken outputs
                amount = totalOutputs[n4].slpToken.amount
            }

            const date = new Date(totalOutputs[n4].time*1000)
            const outputFiltered = {
                localDate: date.toLocaleDateString() + " " + date.toLocaleTimeString(),
                address: await getAddressFromOutputScript(totalOutputs[n4].outputScript),
                amount
            }
            if(eCashAddress !== outputFiltered.address){
                totalOutputsFiltered[totalOutputsFiltered.length] = outputFiltered
            }
        }

        console.table(totalOutputsFiltered)
        /* const utxos = await chronik.script(type, hash).utxos();
        const propertyToSum = 'value';
        if(utxos[0] !== undefined){ 
            const sum = utxos[0].utxos.reduce((accumulator, object) => accumulator + (object[propertyToSum]/100), 0);
            log("balance:")
            log(sum ,"XEC")
        }else{
            log("Your balance in this wallet is 0 XEC")
        } */
    }

}
module.exports = Set