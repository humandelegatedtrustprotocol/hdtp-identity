// Owner-set configuration. Nothing here is a secret.
export const CONFIG = {
  // Google Drive app-data backups. Empty = the Drive backup kind is hidden. The owner's Google
  // Cloud project supplies the client id; the manifest then also needs `"identity"` in
  // permissions and an `oauth2` block with the `drive.appdata` scope (README).
  DRIVE_CLIENT_ID: '',
  // Argon2id parameters for the vault (pact-vault/1). The parameters travel in the vault
  // header, so a vault sealed elsewhere still opens whatever these say.
  KDF: { m_kib: 65536, t: 3, p: 1 },
  // Idle minutes before the unlocked vault is dropped from memory.
  AUTO_LOCK_MINUTES: 15,
  // Default leaf validity, days (SPEC §14.1: at most 398, one year recommended).
  VALID_DAYS: 365,
}
