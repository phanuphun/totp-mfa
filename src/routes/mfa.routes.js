// src/routes/mfa.routes.js
import express from 'express';
import { z } from 'zod';
import knex from '../knex.js';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import { requireAuth } from '../../middlewares/auth.js';

const router = express.Router();

// (เดโม่) เก็บ secret ชั่วคราวแบบ in-memory – โปรดักชันแนะนำ Redis
const pendingSecrets = new Map(); // key: userId, value: base32

// 3.1 เริ่ม Setup: gen secret + QR
router.post('/mfa/totp/setup/start', requireAuth, async (req, res) => {
  const user = await knex('users').where({ id: req.user.uid }).first();
  if (!user) return res.status(404).json({ ok: 0, message: 'User not found' });

  // ถ้าเปิด MFA แล้ว ไม่ต้อง setup ซ้ำ
  if (user.mfaEnabled && user.totpSecret) {
    return res.status(400).json({ ok: 0, message: 'MFA already enabled' });
  }

  const secret = speakeasy.generateSecret({
    length: 20,
    name: `MFA Lab (${user.username})`,
    issuer: 'MFA Lab',
  });

  // เก็บไว้รอยืนยัน (อย่าเพิ่งบันทึก DB)
  pendingSecrets.set(user.id, secret.base32);

  const otpauth = secret.otpauth_url;
  const qrDataURL = await qrcode.toDataURL(otpauth);

  return res.json({
    ok: 1,
    base32: secret.base32,   // (เดโม่) ส่งกลับไปด้วยสำหรับ client ที่อยากแสดงเลขแทน QR
    qr: qrDataURL,           // data:image/png;base64,...
    note: 'Scan QR in Google Authenticator/1Password, then submit 6-digit code to /mfa/totp/setup/verify'
  });
});

// helper สร้าง backup codes (เดโม่: เก็บ plain)
function generateBackupCodes(n = 10) {
  return Array.from({ length: n }, () =>
    Math.random().toString(36).slice(2, 6).toUpperCase() + '-' +
    Math.random().toString(36).slice(2, 6).toUpperCase()
  );
}

// 3.2 ยืนยัน TOTP: รับ code 6 หลัก แล้วเปิดใช้งาน MFA
router.post('/mfa/totp/setup/verify', requireAuth, async (req, res) => {
  const schema = z.object({
    token: z.string().regex(/^\d{6}$/),      // โค้ด 6 หลัก
  });
  console.log(req.body);
  const { token } = schema.parse(req.body);

  const userId = req.user.uid;
  const base32 = pendingSecrets.get(userId);
  if (!base32) {
    return res.status(400).json({ ok: 0, message: 'No pending TOTP setup. Start setup first.' });
  }

  const verified = speakeasy.totp.verify({
    secret: base32,
    encoding: 'base32',
    token,
    window: 1, // อนุโลม clock skew เล็กน้อย
  });

  if (!verified) {
    return res.status(400).json({ ok: 0, message: 'Invalid TOTP code' });
  }

  // สำเร็จ → บันทึก DB: เปิด MFA + เก็บ secret + สร้าง backup codes
  const backupCodes = generateBackupCodes(10);

  await knex('users').where({ id: userId }).update({
    mfaEnabled: true,
    mfaType: 'TOTP',
    totpSecret: base32,                   // โปรดักชันควรเข้ารหัส/แฮช
    backupCodes: JSON.stringify(backupCodes),
    updated_at: knex.fn.now(),
  });

  pendingSecrets.delete(userId);

  return res.json({
    ok: 1,
    message: 'MFA enabled with TOTP',
    backupCodes, // แสดงครั้งเดียว ให้ผู้ใช้บันทึกไว้
  });
});

export default router;
