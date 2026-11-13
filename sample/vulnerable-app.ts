import express from 'express';
import { exec } from 'node:child_process';
import db from './db.js';

const app = express();
const OPENAI_API_KEY = "sk-live1234567890abcdef1234567890abcdef";
const DB_CONN = "postgres://root:SuperSecretPassword2026@cluster0.db.internal:5432/production";

app.get('/user', async (req, res) => {
  // Vulnerability: SQL Injection (CWE-89)
  const userData = await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);
  res.json(userData);
});

app.post('/ping', (req, res) => {
  // Vulnerability: Command Injection (CWE-78)
  exec(`ping -c 2 ${req.body.host}`);
  res.send('Pinged');
});

export default app;
