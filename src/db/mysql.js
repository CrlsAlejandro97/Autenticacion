import mysql from 'mysql2/promise';
import { DB_CONFIG } from '../../config.js';
import { createPool } from 'mysql2';

//Create the connection to database
export const pool = await mysql.createPool({
    host: DB_CONFIG.host,
    user: DB_CONFIG.user,
    password: DB_CONFIG.password,
    database: DB_CONFIG.name,
    waitForConnections: true,
    connectionLimit: 10
})

const testConnection = async () => {
    try{
        const connection = await pool.getConnection()
        connection.release()
        console.log('Mysql Conectado')
    } catch (error){
        console.error('Error conectado mysql:', error.message)
        process.exit(1)
    }
}

testConnection()