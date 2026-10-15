import { PGlite } from '@electric-sql/pglite';

let db;

// ─── Table Creation ──────────────────────────────────────────────────────────
async function createTables() {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      full_name TEXT NOT NULL,
      email TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'customer',
      balance INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS staff_directory (
      staff_code TEXT PRIMARY KEY,
      full_name TEXT NOT NULL,
      department TEXT NOT NULL,
      branch_city TEXT NOT NULL,
      contact_email TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      sender TEXT NOT NULL,
      recipient TEXT NOT NULL,
      amount INTEGER NOT NULL,
      note TEXT DEFAULT '',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS feedback_reviews (
      id SERIAL PRIMARY KEY,
      author TEXT NOT NULL,
      rating INTEGER NOT NULL,
      comment TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_secrets (
      secret_id TEXT PRIMARY KEY,
      vault_key TEXT NOT NULL,
      recovery_pin TEXT NOT NULL
    );
  `);
}

// ─── Seed Data ───────────────────────────────────────────────────────────────
async function seedData() {
  // 5 users with plaintext passwords (for SQLi dump demonstration)
  await db.exec(`
    INSERT INTO users (id, username, password, full_name, email, role, balance) VALUES
      ('USR-001', 'admin',   'SuperSecretAdmin#2026', 'System Administrator', 'admin@sentinelbank.com',      'administrator',    950000),
      ('USR-002', 'alice',   'AliceBank123',           'Alice Johnson',        'alice.johnson@email.com',     'premium_customer', 42500),
      ('USR-003', 'bob',     'BobSecure99',            'Bob Williams',         'bob.williams@email.com',      'customer',         18200),
      ('USR-004', 'charlie', 'CharliePass456',         'Charlie Brown',        'charlie.brown@email.com',     'customer',         8750),
      ('USR-005', 'diana',   'DianaWelcome1',          'Diana Prince',         'diana.prince@email.com',      'vip_customer',     31200);
  `);

  // 6 bank staff records (all TEXT columns for UNION SELECT compatibility)
  await db.exec(`
    INSERT INTO staff_directory (staff_code, full_name, department, branch_city, contact_email) VALUES
      ('SB-1001', 'Rahul Kapoor',    'Information Technology', 'Mumbai',    'rahul.kapoor@sentinelbank.com'),
      ('SB-1002', 'Sarah Mitchell',  'Customer Relations',     'London',    'sarah.mitchell@sentinelbank.com'),
      ('SB-1003', 'Ahmed Hassan',    'Wealth Management',      'Dubai',     'ahmed.hassan@sentinelbank.com'),
      ('SB-1004', 'Priya Sharma',    'Risk and Compliance',    'Delhi',     'priya.sharma@sentinelbank.com'),
      ('SB-1005', 'James O''Brien',  'Treasury Operations',    'New York',  'james.obrien@sentinelbank.com'),
      ('SB-1006', 'Maria Garcia',    'Retail Banking',         'Singapore', 'maria.garcia@sentinelbank.com');
  `);

  // Sample transactions
  await db.exec(`
    INSERT INTO transactions (sender, recipient, amount, note, created_at) VALUES
      ('alice',  'bob',     500,   'Lunch reimbursement',  '2026-10-01T10:30:00Z'),
      ('bob',    'charlie', 200,   'Birthday gift',        '2026-10-05T14:15:00Z'),
      ('admin',  'alice',   10000, 'Quarterly bonus',      '2026-10-10T09:00:00Z'),
      ('diana',  'alice',   1500,  'Freelance payment',    '2026-10-12T11:45:00Z');
  `);

  // Clean seed reviews
  await db.exec(`
    INSERT INTO feedback_reviews (author, rating, comment, created_at) VALUES
      ('alice', 5, 'Excellent banking portal! Very intuitive and easy to use.', '2026-09-15T12:00:00Z'),
      ('bob',   4, 'Good experience overall. Would love to see dark mode support.', '2026-09-20T16:30:00Z'),
      ('diana', 5, 'Premium tier services are fantastic. Highly recommended!',     '2026-09-28T09:15:00Z');
  `);

  // High-value audit secrets (target for information_schema discovery)
  await db.exec(`
    INSERT INTO audit_secrets (secret_id, vault_key, recovery_pin) VALUES
      ('VAULT-001', 'AES-256-KEY-9f8e7d6c5b4a3210', '774291'),
      ('VAULT-002', 'RSA-PRIV-KEY-a1b2c3d4e5f60718', '193847'),
      ('VAULT-003', 'HMAC-SECRET-x5y6z7w8v9u0t1s2', '550163');
  `);
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Initialize the PGlite database.
 * Creates tables and seeds data if the database is empty.
 */
export async function initDatabase() {
  db = new PGlite('./pgdata');

  await createTables();

  // Only seed if tables are empty (first run or after reset)
  const result = await db.query('SELECT COUNT(*)::int AS count FROM users');
  if (result.rows[0].count === 0) {
    await seedData();
    console.log('  ✅ Database seeded with initial data (5 users, 6 staff, 3 secrets)');
  } else {
    console.log('  ✅ Database loaded from existing pgdata/');
  }

  return db;
}

/**
 * Drop all tables and re-create + re-seed them.
 * Called by the "Reset Database" button.
 */
export async function resetDatabase() {
  await db.exec(`
    DROP TABLE IF EXISTS feedback_reviews CASCADE;
    DROP TABLE IF EXISTS transactions    CASCADE;
    DROP TABLE IF EXISTS staff_directory CASCADE;
    DROP TABLE IF EXISTS audit_secrets   CASCADE;
    DROP TABLE IF EXISTS users           CASCADE;
  `);
  await createTables();
  await seedData();
  console.log('  🔄 Database reset and re-seeded');
}

/**
 * Return the current PGlite instance.
 */
export function getDB() {
  return db;
}

