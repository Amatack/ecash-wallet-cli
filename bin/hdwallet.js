#!/usr/bin/env node
const {program} = require("commander")

const SetAdd = require("../commands/hdwalletAdd.js")
const SetBalance = require("../commands/hdwalletBalance.js")
const SetTotalAddresses = require("../commands/hdwalletTotalAddresses.js")
const SetSendXec = require("../commands/hdwalletSendXec.js")
const SetAddressOutputs = require("../commands/hdwalletAddressOutputs.js")
const setAdd = new SetAdd()
const setBalance = new SetBalance()
const setSendXec = new SetSendXec()
const setTotalAddresses = new SetTotalAddresses()
const setAddressOutputs = new SetAddressOutputs()

program
    .version('0.0.1')

program
    .command('start', 'Configure Mnemonic of your wallet.')
    
program
    .command('add')
    .description('Add a new address to your wallet.')
    .action(setAdd.add)

program
    .option('-a, --allAddresses', 'select all your Addresses to your action of the command')
    .command('balance')
    .description('Get your balance from your selected address.')
    .action(setBalance.balance)

program
    .command('addressOutputs')
    .description('Shows complete history of all outputs that have received a etoken or eCash to your specified address, it ignores change backs received.')
    .action(setAddressOutputs.addressOuputs)

program
    .command('totalAddresses')
    .description('Total number of addresses generated and registered.')
    .action(setTotalAddresses.totalAddresses)

program
    .command('sendXec')
    .description('send eCash from your selected address')
    .action(setSendXec.sendXec)

/* if (process.argv.length <= 2) {
    program.outputHelp();
    } else {
    program.parse(process.argv);
} */

program.parse(process.argv);


