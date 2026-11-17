import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { ethers } from "ethers";
import path from "path";
import { fileURLToPath } from "url";
import { webcrypto } from "crypto";
import { getUserByEmail, createUser, updateWallet, updatePromoCounts } from "./db.js";

const crypto = webcrypto;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

const SERVER_KEY_RAW = process.env.SERVER_KEY || "0123456789abcdef0123456789abcdef";
const SERVER_KEY = new TextEncoder().encode(SERVER_KEY_RAW).slice(0, 32);

async function encryptPrivKey(privKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await crypto.subtle.importKey("raw", SERVER_KEY, "AES-GCM", false, ["encrypt"]);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(privKey));
  return {
    iv: Buffer.from(iv).toString("base64"),
    ciphertext: Buffer.from(cipher).toString("base64")
  };
}

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const PROMO_CODES = ["KUPI711","KUPI722","KUPI733","KUPI744","KUPI755","KUPI766","KUPI777"];
const PROMO_BONUS = 10000;
const PROMO_LIMIT = 5;

function auth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Не авторизован" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = getUserByEmail(payload.email);
    if (!user) return res.status(401).json({ error: "Пользователь не найден" });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: "Неверный токен" });
  }
}

app.post("/api/register", async (req, res) => {
  try {
    const { email, nick, password, secret } = req.body;
    if (!email || !nick || !password || !secret) {
      return res.status(400).json({ error: "Заполните все поля" });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Пароль минимум 8 символов" });
    }
    if (getUserByEmail(email)) {
      return res.status(400).json({ error: "Пользователь уже существует" });
    }
    const w = ethers.Wallet.createRandom();
    const passHash = await bcrypt.hash(password, 10);
    const secretHash = await bcrypt.hash(secret, 10);
    const encPriv = await encryptPrivKey(w.privateKey);

    createUser({
      email,
      nick,
      pass_hash: passHash,
      secret_hash: secretHash,
      address: w.address,
      enc_priv: JSON.stringify(encPriv)
    });

    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка регистрации" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = getUserByEmail(email);
    if (!user) return res.status(400).json({ error: "Пользователь не найден" });
    const ok = await bcrypt.compare(password, user.pass_hash);
    if (!ok) return res.status(400).json({ error: "Неверный пароль" });
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  const u = req.user;
  res.json({
    email: u.email,
    nick: u.nick,
    address: u.address,
    wallet: { usd: u.wallet_usd, eur: u.wallet_eur, rub: u.wallet_rub },
    promoCounts: JSON.parse(u.promo_counts || "{}")
  });
});

app.post("/api/promo", auth, (req, res) => {
  const { code } = req.body;
  const u = req.user;
  const up = String(code || "").trim().toUpperCase();
  if (!PROMO_CODES.includes(up)) return res.status(400).json({ error: "Неверный промокод" });
  const counts = JSON.parse(u.promo_counts || "{}");
  const used = counts[up] || 0;
  if (used >= PROMO_LIMIT) return res.status(400).json({ error: "Лимит активаций исчерпан" });

  counts[up] = used + 1;
  const wallet = {
    usd: u.wallet_usd + PROMO_BONUS,
    eur: u.wallet_eur + PROMO_BONUS,
    rub: u.wallet_rub + PROMO_BONUS
  };
  updateWallet(u.email, wallet);
  updatePromoCounts(u.email, counts);
  res.json({ ok: true, used: counts[up], wallet });
});

app.post("/api/exchange", auth, (req, res) => {
  const { from, to, amount, rate } = req.body;
  if (!["usd","eur","rub"].includes(from) || !["usd","eur","rub"].includes(to) || from === to) {
    return res.status(400).json({ error: "Неверные валюты" });
  }
  if (!amount || amount <= 0 || !rate || rate <= 0) {
    return res.status(400).json({ error: "Неверная сумма или курс" });
  }
  const u = req.user;
  const wallet = { usd: u.wallet_usd, eur: u.wallet_eur, rub: u.wallet_rub };
  if (amount > wallet[from]) return res.status(400).json({ error: "Недостаточно средств" });

  const gross = amount * rate;
  const fee = gross * 0.01;
  const net = gross - fee;
  wallet[from] -= amount;
  wallet[to] += net;
  updateWallet(u.email, wallet);
  res.json({ ok: true, wallet, received: net, fee });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`✅ Сервер запущен: http://localhost:${PORT}`);
});
