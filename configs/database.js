const log = require('./constants')

async function createDatabase() {
    
    try{
        
        const { JSONFilePreset } = await import('lowdb/node')
        
        // Read or create db.json
        const defaultData = { account: [] }
        db = await JSONFilePreset('./data/account.json', defaultData)
        if(db.data.account.length !== 0) return
        console.log("Create new wallet ")
        await db.update(({ account }) => account.push('myMnemonic'))

        const defaultData2 = { addresses: [] }
        db = await JSONFilePreset('./data/addresses.json', defaultData2)
        await db.update(({ addresses }) => addresses.push('myFirstAddressForDefault'))
        console.log("Db created successfully")
    } catch (error) {
        // Handle the error or initialize a new database if the file doesn't exist
        console.error('Error at initialize a new database:', error);
        return
    }
}

module.exports = createDatabase;