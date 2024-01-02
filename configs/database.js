const fs = require('fs').promises;

async function createDatabase() {
    
    try{
        const newFolder = 'data';

        await fs.mkdir(newFolder)
        
        console.log('Carpeta creada exitosamente:', newFolder);
        
        const { JSONFilePreset } = await import('lowdb/node')
        // Read or create db.json
        const defaultData = { account: [] }
        const db = await JSONFilePreset('./data/account.json', defaultData)
        await db.update(({ account }) => account.push('myMnemonic'))

        const defaultData2 = { addresses: [] }
        const db2 = await JSONFilePreset('./data/addresses.json', defaultData2)
        await db2.update(({ addresses }) => addresses.push('myFirstAddressForDefault'))
    } catch (error) {
        // Handle the error or initialize a new database if the file doesn't exist
        console.error('Error at initialize a new database:', error);
    }
}

module.exports = createDatabase;