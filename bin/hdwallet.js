#!/usr/bin/env node
const {program} = require("commander")

const SetAdd = require("../commands/hdwalletAdd.js")
const SetBalance = require("../commands/hdwalletBalance.js")
const SetTotalAddresses = require("../commands/hdwalletTotalAddresses.js")
const SetSendXec = require("../commands/hdwalletSendXec.js")
const setAdd = new SetAdd()
const setBalance = new SetBalance()
const setSendXec = new SetSendXec()
const setTotalAddresses = new SetTotalAddresses()

program
    .version('0.0.1')
    .option('-a, --allAddresses', 'select all your Addresses to your action of the command')

program
    .command('start', 'Configure Mnemonic of your wallet.')
    
program
    .command('add')
    .description('Add a new address to your wallet.')
    .action(setAdd.add)

program
    .option('-a, --allAddresses <allAddresses>', 'select all your Addresses to your action of the command')
    .command('balance')
    .description('Get your balance from your selected address.')
    .action(setBalance.balance)

program
    .command('putAlias', 'Put a Alias to your selected address')

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


