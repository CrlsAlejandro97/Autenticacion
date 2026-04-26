import axios from 'axios'
import { config } from '../config.js'

export const getDbCredentials = async () => {
  const res = await axios.get(
    `${config.vault.addr}/v1/database/creds/${config.vault.role}`,
    {
      headers: {
        'X-Vault-Token': config.vault.token
      }
    }
  )

  return {
    user: res.data.data.username,
    password: res.data.data.password,
    leaseDuration: res.data.lease_duration
  }
}
