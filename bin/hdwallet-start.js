const program = require('commander')
const Set = require("../commands/hdwalletStart.js")

const set = new Set()

program
    .command('generate')
    .description('Generate new Mnemonic randomly')
    .action(set.generate)
    //.action(set.addPlayer)

program
    .command('enter')
    .description('Enter Mnemonic and set it as default every time you use this wallet')
    .action(()=> console.log('Enter Mnemonic and set it as default every time you use this wallet'))
    //.action(set.removePlayer)

program
    .parse(process.argv)

    