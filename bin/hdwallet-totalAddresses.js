const getConnection = require("../db/getConnection.js");
const { log } = require('../configs/constants.js')

async function totalAddresses() {
    const db = await getConnection("addresses")
        
    log("total addresses:", db.data.addresses.length)
    
}

totalAddresses()