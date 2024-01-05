#!/usr/bin/env node
const program = require("commander")


program
    .option('-a, --allAddresses', 'select all your Addresses to your action of the command')

program
    .version('0.0.1')
    .command('start', 'Configure Mnemonic of your wallet.')
    .command('add', 'Add a new address to your wallet.')
    .command('balance', 'Get your balance from your selected address.')
    .command('history', 'Get your history of transactions from your selected address.')
    .command('remove', 'remove a address without coins of your wallet.')
    .command('putAlias', 'Put a Alias to your selected address')
    .command('send', 'send eCash from your selected address')
    .parse(process.argv)
    