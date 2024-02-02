async function getConnection(jsonName){
    const { JSONFilePreset } = await import('lowdb/node')
    const defaultData = { account: [] }
    const path = "./data/"
    const extension = ".json"
    const db = await JSONFilePreset(path+jsonName+extension, defaultData)
    await db.read()
    return db
}

module.exports = getConnection