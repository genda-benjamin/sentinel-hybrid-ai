import express from 'express';
import { getUserProfile } from '../services/userService.js';

const app = express();

// Entrypoint Source: User input from HTTP GET parameter
app.get('/api/user', async (req, res) => {
  const userId = req.query.id;
  const result = await getUserProfile(userId);
  res.json(result);
});

export default app;
