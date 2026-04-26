import mysql from 'mysql2/promise'
import { getDbCredentials } from '../services/vault.js'
import { config } from '../config.js'

let connection = null

export const getConnection = async () => {
  if (connection) return connection

  const creds = await getDbCredentials()

  console.log('🔐 Credenciales dinámicas obtenidas de Vault')

  connection = await mysql.createConnection({
    host: config.db.host,
    user: creds.user,
    password: creds.password,
    database: config.db.name
  })

  return connection
}
