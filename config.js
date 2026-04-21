import 'dotenv/config'

export const ENV = process.env.NODE_ENV || 'development'

export const DB_CONFIG = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    name: process.env.DB_NAME,
    port: Number(process.env.DB_PORT || 3306)
}

export const server = {
    port:Number(process.env.PORT || 3000)
}

export const SALT_ROUNDS = Number(process.env.SALT_ROUNDS || 10)
export const JWT_SECRET = process.env.JWT_SECRET
export const JWT_SECRET_IN = '1h'

// Validación de variables críticas
;[
  'DB_HOST',
  'DB_USER',
  'DB_PASSWORD',
  'DB_NAME',
  'JWT_SECRET'
].forEach((key) => {
  if (!process.env[key]) {
    throw new Error(`❌ Missing env var: ${key}`)
  }
})