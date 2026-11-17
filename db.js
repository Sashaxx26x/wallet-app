import Database from "better-sqlite3";

const DB_PATH = process.env.DB_PATH || "wallet.db";
export const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    nick TEXT NOT NULL,
    pass_hash TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    address TEXT NOT NULL,
    enc_priv TEXT NOT NULL,
    wallet_usd REAL DEFAULT 0,
    wallet_eur REAL DEFAULT 0,
    wallet_rub REAL DEFAULT 0,
    promo_counts TEXT DEFAULT '{}',
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
`);

export function getUserByEmail(email) {
  return db.prepare("SELECT * FROM users WHERE email = ?").get(email);
}

export function createUser(data) {
  return db.prepare(`
    INSERT INTO users (email, nick, pass_hash, secret_hash, address, enc_priv)
    VALUES (@email, @nick, @pass_hash, @secret_hash, @address, @enc_priv)
  `).run(data);
}

export function updateWallet(email, wallet) {
  db.prepare(`
    UPDATE users SET wallet_usd = ?, wallet_eur = ?, wallet_rub = ?
    WHERE email = ?
  `).run(wallet.usd, wallet.eur, wallet.rub, email);
}

export function updatePromoCounts(email, promoCounts) {
  db.prepare("UPDATE users SET promo_counts = ? WHERE email = ?")
    .run(JSON.stringify(promoCounts), email);
}
