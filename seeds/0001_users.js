// seeds/0001_users.js
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';

export async function seed(knex) {
  await knex('mfa_trust_devices').del();
  await knex('users').del();

  const passwordHash = await bcrypt.hash('P@ssw0rd!', 12);

  await knex('users').insert([
    {
      id: uuid(),
      username: 'alice',
      passwordHash,
      mfaEnabled: false,
      mfaType: null,
      totpSecret: null,
      backupCodes: JSON.stringify([]),
      created_at: knex.fn.now(),
      updated_at: knex.fn.now()
    }
  ]);
}
