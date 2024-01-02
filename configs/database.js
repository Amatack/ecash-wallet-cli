async function createConnection() {
    //const file = join(__Dirname, '../db.json');
    try{
        const { JSONFilePreset } = await import('lowdb/node')
        // Read or create db.json
        const defaultData = { posts: [] }
        const db = await JSONFilePreset('./data/db.json', defaultData)
        await db.update(({ posts }) => posts.push('hello world'))
        
        // Alternatively you can call db.write() explicitely later
        // to write to db.json
        db.data.posts.push('hello world')
        await db.write()
        console.log(db)
        
    } catch (error) {
        // Handle the error or initialize a new database if the file doesn't exist
        console.error('Error reading file:', error);

        // Create a new lowdb instance with an empty object
        db = new Low({});

        console.log(db);
    }
}

createConnection();