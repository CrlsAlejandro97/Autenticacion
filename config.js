import 'dotenv/config'

export const ENV = process.env.NODE_ENV || 'development'

//VAULT
export const config = {
  vault: {
    addr: process.env.VAULT_ADDR,
    token: process.env.VAULT_TOKEN,
    role: process.env.VAULT_ROLE
  },
  db: {
    host: '192.168.0.13',
    name: 'db'
  }
}


export const server = {
    port:Number(process.env.PORT || 3000)
}

export const SALT_ROUNDS = Number(process.env.SALT_ROUNDS || 10)
export const JWT_SECRET = process.env.JWT_SECRETS
export const JWT_SECRET_IN = '1h'

// Validación de variables críticas
;[
  'DB_HOST',
  'DB_USER',
  'DB_PASSWORD',
  'DB_NAME',
  'JWT_SECRETS'
].forEach((key) => {
  if (!process.env[key]) {
    throw new Error(`❌ Missing env var: ${key}`)
  }
})