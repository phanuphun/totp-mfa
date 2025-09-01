import 'dotenv/config';
import express from 'express';
import authRoutes from './routes/auth.routes.js';
import mfaRoutes from './routes/mfa.routes.js';
import cors from 'cors';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors())

app.get('/health', (_req, res) => res.json({ ok: 1, service: 'mfa-lab', ts: new Date().toISOString() }));

app.use(authRoutes);
app.use(mfaRoutes);

app.listen(3000, () => {
    console.log('MFA Lab listening on http://localhost:3000');
});