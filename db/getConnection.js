async function getConnection(jsonName){
    const { JSONFilePreset } = await import('lowdb/node')
    const defaultData = {};
    defaultData[jsonName] = []
    const path = "./data/"
    const extension = ".json"
    let completePath = path+jsonName+extension
    const db = await JSONFilePreset(completePath, defaultData)
    await db.read()
    return db
}

module.exports = getConnection