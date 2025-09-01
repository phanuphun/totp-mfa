// src/routes/auth.routes.js
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import knex from '../knex.js';
import speakeasy from 'speakeasy';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'dev_dev_secret_change_me';

// POST /auth/login
// body: { username, password, deviceId? }
router.post('/auth/login', async (req, res) => {
  try {
    const schema = z.object({
      username: z.string().min(1),
      password: z.string().min(1),
      deviceId: z.string().optional(), // ไว้ใช้เช็ค trusted device ในสเต็ปถัดไป
    });
    const { username, password } = schema.parse(req.body);

    // 1) หา user
    const user = await knex('users').where({ username }).first();
    if (!user) return res.status(401).json({ ok: 0, message: 'Invalid credentials' });

    // 2) ตรวจรหัสผ่าน
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ ok: 0, message: 'Invalid credentials' });

    // 3) ถ้าเปิด MFA → ส่ง tempToken (ยังไม่ให้เข้า)
    if (user.mfaEnabled) {
      const tempToken = jwt.sign(
        { id: user.id, stage: 'mfa' },
        JWT_SECRET,
        { expiresIn: '5m' } // อายุสั้น 5 นาที
      );
      return res.json({ ok: 1, mfa_required: true, tempToken });
    }

    // 4) ถ้ายังไม่เปิด MFA → ออก access token ปกติ (อายุสั้น ๆ ไว้ก่อน)
    const accessToken = jwt.sign({ uid: user.id }, JWT_SECRET, { expiresIn: '1h' });
    return res.json({ ok: 1, mfa_required: false, accessToken });
  } catch (err) {
    if (err instanceof z.ZodError) {
      return res.status(400).json({ ok: 0, message: 'Bad request', issues: err.flatten() });
    }
    console.error(err);
    return res.status(500).json({ ok: 0, message: 'Internal error' });
  }
});

router.post('/auth/mfa/verify', async (req, res) => {
  // ต้องแนบ Authorization: Bearer <pending-mfa token> มา
  const auth = req.headers.authorization || '';
  const pendingToken = auth.startsWith('Bearer ') ? auth.slice(7) : '';

  let payload;
  try {
    payload = jwt.verify(pendingToken, JWT_SECRET);
    if (payload.stage !== 'mfa') throw new Error('Not a pending-mfa token');
  } catch {
    return res.status(401).json({ ok: 0, message: 'Invalid or expired pending token' });
  }

  const schema = z.object({ code: z.string().regex(/^\d{6}$/) });
  const { code } = schema.parse(req.body);
  console.log("Payload" , payload);
  const user = await knex('users').where({ id: payload.id }).first();
  if (!user?.mfaEnabled || !user?.totpSecret) {
    return res.status(400).json({ ok: 0, message: 'MFA not enabled for this user' });
  }

  const verified = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token: code,
    step: 30,
    window: 1,
  });

  if (!verified) {
    return res.status(400).json({ ok: 0, message: 'Invalid or expired TOTP code' });
  }

  const access = jwt.sign(
    { sub: user.id, role: user.role, amr: ['pwd','otp'], mfa: true, auth_time: Math.floor(Date.now()/1000) },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  await knex('users').where({ id: user.id }).update({ updated_at: knex.fn.now() });

  res.json({ ok: 1, accessToken: access });
});
export default router;
