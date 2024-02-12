#!/usr/bin/env node
const program = require("commander")

program
    .option('-a, --allAddresses', 'select all your Addresses to your action of the command')

program
    .version('0.0.1')
    .command('start', 'Configure Mnemonic of your wallet.')
    .command('add', 'Add a new address to your wallet.')
    .command('balance', 'Get your balance from your selected address.')
    .command('putAlias', 'Put a Alias to your selected address')
    .command('totalAddresses', 'Total number of addresses generated and registered.')
    .command('sendXec', 'send eCash from your selected address')
    .parse(process.argv)
    