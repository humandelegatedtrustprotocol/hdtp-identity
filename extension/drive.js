// Google Drive app-data backups: one file per vault in the app-data folder, overwritten on every
// change, invisible to the person's other Drive apps. Enabled only when config.js carries the
// owner's OAuth client id, and then the manifest also needs the `identity` permission and an
// `oauth2` block (README).
import { CONFIG } from './config.js'

const API = 'https://www.googleapis.com/drive/v3'
const UPLOAD = 'https://www.googleapis.com/upload/drive/v3'
const FILE = 'pact-vault.json'

export const driveEnabled = () => !!CONFIG.DRIVE_CLIENT_ID && !!(chrome.identity && chrome.identity.getAuthToken)

async function token(interactive) {
  const { token } = await chrome.identity.getAuthToken({ interactive })
  if (!token) throw new Error('no Drive authorisation')
  return token
}

async function api(path, init = {}, interactive = true) {
  const t = await token(interactive)
  const res = await fetch(path, { ...init, headers: { ...(init.headers || {}), authorization: `Bearer ${t}` } })
  if (!res.ok) throw new Error(`Drive answered ${res.status}`)
  return res
}

async function find() {
  const res = await api(`${API}/files?spaces=appDataFolder&fields=files(id,name,modifiedTime)&q=${encodeURIComponent(`name='${FILE}'`)}`)
  const { files } = await res.json()
  return files && files[0] ? files[0] : null
}

/** Uploads the sealed vault document, replacing the previous copy. */
export async function upload(vault) {
  const existing = await find()
  const body = new FormData()
  body.append('metadata', new Blob([JSON.stringify(existing ? {} : { name: FILE, parents: ['appDataFolder'] })], { type: 'application/json' }))
  body.append('file', new Blob([JSON.stringify(vault)], { type: 'application/json' }))
  const url = existing ? `${UPLOAD}/files/${existing.id}?uploadType=multipart` : `${UPLOAD}/files?uploadType=multipart`
  const res = await api(url, { method: existing ? 'PATCH' : 'POST', body })
  return res.json()
}

/** Lists what the app-data folder holds. */
export async function list() {
  const f = await find()
  return f ? [f] : []
}

/** Downloads the sealed vault document. */
export async function download() {
  const f = await find()
  if (!f) throw new Error('no vault in Drive')
  const res = await api(`${API}/files/${f.id}?alt=media`)
  return res.json()
}
