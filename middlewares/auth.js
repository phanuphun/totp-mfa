// src/middleware/auth.js
import jwt from 'jsonwebtoken';


const JWT_SECRET = process.env.JWT_SECRET || 'dev_dev_secret_change_me';

export function requireAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ ok: 0, message: 'Missing token' });
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { uid: payload.uid };
    next();
  } catch (e) {
    return res.status(401).json({ ok: 0, message: 'Invalid token' });
  }
}