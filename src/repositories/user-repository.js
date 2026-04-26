import { getConnection } from '../db/mysql.js'
import bcrypt from 'bcrypt'
import crypto from 'crypto'
import { config } from '../../config.js'

export class UserRepository {

  static async create({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const conn = await getConnection()

    const [users] = await conn.query(
      'SELECT * FROM users WHERE username = ?', [username]
    )

    if (users.length > 0) {
      throw new Error("el usuario ya existe")
    }

    const id = crypto.randomUUID()
    const hashedPassword = await bcrypt.hash(
      password,
      config.security.saltRounds
    )

    await conn.query(
      'INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)',
      [id, username, hashedPassword]
    )

    return id
  }

  static async login({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const conn = await getConnection()

    const [users] = await conn.query(
      'SELECT * FROM users WHERE username = ?', [username]
    )

    const user = users[0]
    if (!user) throw new Error('el usuario no existe')

    const isValid = await bcrypt.compare(password, user.password_hash)
    if (!isValid) throw new Error('contraseña incorrecta')

    const { password_hash: _, ...publicUser } = user
    return publicUser
  }
}

class Validation {
  static username(username) {
    if (typeof username !== 'string') throw new Error('username must be a string')
    if (username.length < 3) throw new Error('username must be at least 3 characters')
  }

  static password(password) {
    if (typeof password !== 'string') throw new Error('password must be a string')
    if (password.length < 6) throw new Error('password must be at least 6 characters')
  }
}