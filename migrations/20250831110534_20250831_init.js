// migrations/20250831_init.js
export async function up(knex) {
  await knex.schema.createTable('users', (t) => {
    t.uuid('id').primary();
    t.string('username').notNullable().unique();
    t.string('passwordHash').notNullable();
    t.boolean('mfaEnabled').notNullable().defaultTo(false);
    t.string('mfaType').nullable();        // 'TOTP' | (สำรอง 'WEBAUTHN' ในอนาคต)
    t.string('totpSecret').nullable();     // เก็บ base32 (เดโม) - โปรดักชันควรเข้ารหัส/แฮช
    t.json('backupCodes').nullable();      // เดโมเก็บ plain, โปรดักชันให้แฮช
    t.timestamps(true, true);
  });

  await knex.schema.createTable('mfa_trust_devices', (t) => {
    t.uuid('id').primary();
    t.uuid('userId').notNullable().index()
      .references('id').inTable('users').onDelete('CASCADE');
    t.string('deviceId').notNullable().index(); // ฟิงเกอร์พรินต์จาก client (เช่น hash ของ UA+platform)
    t.timestamp('expiresAt').notNullable();
    t.unique(['userId','deviceId']);
    t.timestamps(true, true);
  });
}

export async function down(knex) {
  await knex.schema.dropTableIfExists('mfa_trust_devices');
  await knex.schema.dropTableIfExists('users');
}
