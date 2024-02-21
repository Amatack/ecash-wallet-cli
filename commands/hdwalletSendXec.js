
const { ChronikClient } = require('chronik-client');
//const { coinSelect } = require('ecash-coinselect');
const { coinSelect } = require('../modules/ecash-coinselect')
const ecashaddr = require('ecashaddrjs')
const getConnection = require("../db/getConnection.js");
const inquirer = require('inquirer')
const {program} = require('commander')
const utxolib = require('../modules/@bitgo/utxo-lib')

const { log, chronikInstance, derivationPath } = require('../configs/constants.js');
const convertXecToSatoshis = require('../utils/convertXecToSatoshis.js')
const getUtxosFromAddress = require('../utils/getUtxosFromAddress.js')
const { decryptMnemonic , deriveWallet} = require('../utils/utils.js');
const convertNumber = require('../utils/convertNumber.js');


class Set {
    sendXec = async ()=>{
        const HASHTYPES = {
            SIGHASH_ALL: 0x01,
            SIGHASH_FORKID: 0x40,
        };

        const dbAddresses = await getConnection("addresses")
        const chronik = new ChronikClient(chronikInstance);

        const dbAccount = await getConnection("account")
        const ivData = dbAccount.data.account[0].iv.data
        const ivBuffer = Buffer.from(ivData);
        const encryptedMnemonic = dbAccount.data.account[0].mnemonic
        const indexAndAddress = []  

        for(let i = 0; i < dbAddresses.data.addresses.length; i++){
            indexAndAddress[i] = dbAddresses.data.addresses[i].index +" "+dbAddresses.data.addresses[i].ecashAddress
        }

        if(program.rawArgs[2] === "-a" || program.rawArgs[2] === "--allAddresses" || program.rawArgs[3] === "-a" || program.rawArgs[3] === "--allAddresses"){
            log("executed with -a option")

            const options = [{
                name: "sender",
                type: "checkbox",
                message: "From which addresses do you want to send the funds?: ",
                choices: indexAndAddress
            },
            {
                name: "receiver",
                type: "input",
                message: "Write eCash address of receiver:"
            },
            {
                name: "amountOfXec",
                type: "input",
                message: "Amount of xec for sending:"
            },
            {
                name: "password",
                type: "password",
                message: "Password to confirm broadcasting:"
            }
            ]
            const result = await inquirer.prompt(options)
            
            const {amountOfXec,receiver, password} = result
            if(receiver.length !== 48){
                log("You must enter an valid eCash address")
                return
            }

            if(Number(amountOfXec) < 5.5){
                log("you can only send amounts greater than 5.5")
                return
            }
            const wallets = []

            let txBuilder = utxolib.bitgo.createTransactionBuilderForNetwork(
                utxolib.networks.ecash,
            );

            
            //no need to select index or wallet
            const walletsUtxosNumber = []
            const utxosLogic = []
            const allUtxos = []
            
            let utxosValueToUse = 0
            let concatenatedUtxos = []
            const utxosECPair = []
            // ** Part 1 - Convert user input into satoshis **
    
            // Convert the XEC amount to satoshis
            // Note: 'Number' type is used throughout this example in favour
            // of BigInt as XEC amounts can have decimals
            let sendAmountInSats = convertXecToSatoshis(amountOfXec);
            log("Wallets used for this transaction: ")
            for(let i=0; i<result.sender.length; i++){
                //select each address due interaction 
                const sender = result.sender[i]
                //log("sender: ", sender)
                const indexAndAddressSelected = sender.split(" ")
                
                const index = indexAndAddressSelected[0]
                const eCashAddress = indexAndAddressSelected[1]

                const decryptedMnemonic = decryptMnemonic(encryptedMnemonic, ivBuffer, password)
            
                wallets[i] = await deriveWallet(decryptedMnemonic, derivationPath, eCashAddress, index)
                //log("wallets: ", wallets)
                utxosLogic[i] = await getUtxosFromAddress(
                    chronik,
                    wallets[i].address,
                );
                
                //empty address
                if(utxosLogic[i][0] !== undefined){
                    const {utxos} = utxosLogic[i][0]
                    const utxosNumber = utxos.length
                    //walletsUtxosNumber[i] = utxosNumber

                    allUtxos[i] = utxos
                
                        
                    //log("utxos: ",utxos)
                    let showWalletUsed = true
                    concatenatedUtxos = concatenatedUtxos.concat(allUtxos[i])
                    
                        for(let n = 0; n<utxosNumber;n++){
                            //log("amountOfXec: ", amountOfXec)
                            //log("utxosValueToUse: ", utxosValueToUse)
                            if(amountOfXec > utxosValueToUse){
                                // i represents each wallet and n represents each utxo
                                let xecWithDecimal = convertNumber(Number(allUtxos[i][n].value))
                                utxosValueToUse += Number(xecWithDecimal)
                                
                                utxosECPair[utxosECPair.length] = utxolib.ECPair.fromWIF(
                                    wallets[i].fundingWif,
                                    utxolib.networks.ecash,
                                    );
                                    if(showWalletUsed === true){
                                        log(wallets[i].address)
                                    }
                                    showWalletUsed = false
                                
                                //It is better to see all the values of the array by log function
                                
                            }else break
                        }
                        //log("Final Result of utxosECPair: ", utxosECPair)
                    
                }
            }
            
            const targetOutputs = [
            {
                value: sendAmountInSats,
                address: receiver,
            },
            ];

            // Call on ecash-coinselect to select enough XEC utxos and outputs inclusive of change
            let { inputs, outputs } = coinSelect(concatenatedUtxos, targetOutputs);

            //let { inputs:inputs2 } = coinSelect(utxos2, targetOutputs);
            // Add the selected xec utxos to the tx builder as inputs
            for (const input of inputs) {
                txBuilder.addInput(input.outpoint.txid, input.outpoint.outIdx);
            }
            /* for (const input of inputs2) {
                txBuilder.addInput(input.outpoint.txid, input.outpoint.outIdx);
            } */
            // ** Part 4. Generate the tx outputs **

            for (const output of outputs) {
                if (!output.address) {
                    // Note that you may now have a change output with no specified address
                    // This is expected behavior of coinSelect
                    // User provides target output, coinSelect adds change output if necessary (with no address key)

                    // Change address is wallet address
                    output.address = wallets[0].address;
                }

                txBuilder.addOutput(
                    // utxo-lib's txBuilder currently only interacts with the legacy address
                    // TODO add cashaddr support for eCash to txBuilder in utxo-lib
                    ecashaddr.toLegacy(output.address),
                    output.value,
                );
            }


            // Loop through all the collected XEC input utxos
            for (let i = 0; i < inputs.length; i++) {
                const thisUtxo = inputs[i];
                //log("utxosECPair[i]: ",utxosECPair[i])
                // Sign this tx
                
                txBuilder.sign(
                    i, // vin
                    utxosECPair[i], // keyPair
                    undefined, // redeemScript, typically used for P2SH addresses
                    HASHTYPES.SIGHASH_ALL | HASHTYPES.SIGHASH_FORKID, // hashType
                    parseInt(thisUtxo.value), // value of this single utxo
                );
            }

            // ** Part 6. Build the transaction **

            const tx = txBuilder.build();

            const estimatedFee = tx.byteLength();
            log('The estimated fee for this transaction is:', estimatedFee, 'satoshis');

            // Convert to raw hex for use in chronik
            const hex = tx.toHex();
            //log("hex: ",hex)
            // ** Part 7. Broadcast raw hex to the network via chronik **

            // Example successful chronik.broadcastTx() response:
            //    {"txid":"0075130c9ecb342b5162bb1a8a870e69c935ea0c9b2353a967cda404401acf19"}
            const response = await chronik.broadcastTx(hex);
            if (!response) {
                throw new Error('sendXec(): Empty chronik broadcast response');
            } 
            
            log("txid: ", response.txid)
            return
        }
        
        try {

            const options = [
                {
                    name: "sender",
                    type: "list",
                    message: "From which address do you want to send the funds?: ",
                    choices: indexAndAddress
                },
                {
                    name: "receiver",
                    type: "input",
                    message: "Write eCash address of receiver:"
                },
                {
                    name: "amountOfXec",
                    type: "input",
                    message: "Amount of xec for sending:"
                },
                {
                    name: "password",
                    type: "password",
                    message: "Password to confirm broadcasting:"
                }
            ]
            
            const result = await inquirer.prompt(options)
            const indexAndAddressSelected = result.sender.split(" ")
            const sender = String(indexAndAddressSelected[indexAndAddressSelected.length-1])
            const index = indexAndAddressSelected[0]
            
            const {amountOfXec,receiver, password} = result
            if(receiver.length !== 48){
                log("You must enter an valid eCash address")
                return
            }

            if(Number(amountOfXec) < 5.5){
                log("you can only send amounts greater than 5.5")
                return
            }
            
            const decryptedMnemonic = decryptMnemonic(encryptedMnemonic, ivBuffer, password)
            
            const wallet = await deriveWallet(decryptedMnemonic, derivationPath, sender, index)
            
            // In JS, Number.MAX_SAFE_INTEGER = 9007199254740991. Since total supply of
            // satoshis in eCash is 2100000000000000, it is safe to use JS native numbers

            // Initialize the bitgo transaction builder to the XEC network
            // which will be used to build and sign the transaction
            let txBuilder = utxolib.bitgo.createTransactionBuilderForNetwork(
                utxolib.networks.ecash,
            );

            // ** Part 1 - Convert user input into satoshis **

            // Convert the XEC amount to satoshis
            // Note: 'Number' type is used throughout this example in favour
            // of BigInt as XEC amounts can have decimals
            let sendAmountInSats = convertXecToSatoshis(amountOfXec);

            // ** Part 2. Extract the sending wallet's XEC utxos **
            
            // Retrieve the sending wallet's XEC + SLP utxos using the function from the getUtxosFromAddress.js example
            const combinedUtxos = await getUtxosFromAddress(
                chronik,
                wallet.address,
            );

            // The eCash utxos are in the first element of the response (combinedUtxos) from Chronik
            // This is due to chronik.script().utxos() returning:
            // a) an empty array if there are no utxos at the address; or
            // b) an array of one object with the key 'utxos' if there are utxos
            const { utxos } = combinedUtxos[0];
            // ** Part 3. Collect enough XEC utxos (tx inputs) to pay for sendAmountInSats + fees **

            // Define the recipients (i.e. outputs) of this tx and the amounts in sats
            // In this case, we have only one targetOutput. coinSelect accepts an array input.
            const targetOutputs = [
                {
                    value: sendAmountInSats,
                    address: receiver,
                },
            ];
            //log("utxos: ", utxos)
            // Call on ecash-coinselect to select enough XEC utxos and outputs inclusive of change
            let { inputs, outputs } = coinSelect( utxos , targetOutputs);
            
            // Add the selected xec utxos to the tx builder as inputs
            for (const input of inputs) {
                txBuilder.addInput(input.outpoint.txid, input.outpoint.outIdx);
            }

            // ** Part 4. Generate the tx outputs **

            for (const output of outputs) {
                if (!output.address) {
                    // Note that you may now have a change output with no specified address
                    // This is expected behavior of coinSelect
                    // User provides target output, coinSelect adds change output if necessary (with no address key)

                    // Change address is wallet address
                    output.address = wallet.address;
                }

                txBuilder.addOutput(
                    // utxo-lib's txBuilder currently only interacts with the legacy address
                    // TODO add cashaddr support for eCash to txBuilder in utxo-lib
                    ecashaddr.toLegacy(output.address),
                    output.value,
                );
            }

            // ** Part 5. Sign the transaction **

            // Extract the key pair based on the wallet wif
            const utxoECPair = utxolib.ECPair.fromWIF(
                wallet.fundingWif,
                utxolib.networks.ecash,
            );

            // Loop through all the collected XEC input utxos
            for (let i = 0; i < inputs.length; i++) {
                const thisUtxo = inputs[i];

                // Sign this tx
                txBuilder.sign(
                    i, // vin
                    utxoECPair, // keyPair
                    undefined, // redeemScript, typically used for P2SH addresses
                    HASHTYPES.SIGHASH_ALL | HASHTYPES.SIGHASH_FORKID, // hashType
                    parseInt(thisUtxo.value), // value of this single utxo
                );
            }

            // ** Part 6. Build the transaction **

            const tx = txBuilder.build();
            const estimatedFee = tx.byteLength();
            log('The estimated fee for this transaction is:', estimatedFee, 'satoshis');
            // Convert to raw hex for use in chronik
            const hex = tx.toHex();

            // ** Part 7. Broadcast raw hex to the network via chronik **

            // Example successful chronik.broadcastTx() response:
            //    {"txid":"0075130c9ecb342b5162bb1a8a870e69c935ea0c9b2353a967cda404401acf19"}
            const response = await chronik.broadcastTx(hex);
            if (!response) {
                throw new Error('Empty chronik broadcast response');
            }

            log("txid: ",response.txid) 
        } catch (err) {
            log(`Error sending XEC transaction: `, err);
            throw err;
        }
    }
}

module.exports = Set