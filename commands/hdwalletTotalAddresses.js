
const getConnection = require("../db/getConnection.js");
const { log } = require('../configs/constants.js')

class Set {
    totalAddresses = async ()=>{
        
        const dbAddresses = await getConnection("addresses")
        
        log("total addresses:", dbAddresses.data.addresses.length)
        
    }

}
module.exports = Set