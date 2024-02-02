
const inquirer = require('inquirer')

const getConnection = require("../db/getConnection.js")

async function hdwalletBalance() {
    /* const { JSONFilePreset } = await import('lowdb/node')

    const defaultData = { account: [] }
    const db = await JSONFilePreset('./data/addresses.json', defaultData)
    await db.read() */
    const db = await getConnection("addresses")
    console.log("addresses: ",db.data)

    const options = [
        {
            name: "options",
            type: "list",
            message: "¿Qué quieres hacer?",
            choices: db.data.addresses
        }
    ]
    const result = await inquirer.prompt(options)
}

hdwalletBalance()