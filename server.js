// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  SentinelBank — Main Express Server (port 5000)                        ║
// ║  Serves the frontend, mounts vulnerable & safe API routes,             ║
// ║  manages sessions, and provides DB reset functionality.                ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { initDatabase, resetDatabase, getDB } from './db/init.js';
import { createVulnerableRouter } from './backend/routes/vulnerable.js';
import { createSafeRouter } from './backend/routes/safe.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 5000;

// ── In-Memory Session Store ──────────────────────────────────────────────
// Map<sessionId, { userId, username, fullName, email, role, balance, csrfToken? }>
const sessions = new Map();

// ── Middleware ────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS: Allow the attacker server (port 5500) — needed for CSRF demo
app.use(cors({
  origin: ['http://localhost:5000', 'http://localhost:5500'],
  credentials: true,
}));

// Serve frontend static files
app.use(express.static(path.join(__dirname, 'frontend')));

// ── Mount API Routes ─────────────────────────────────────────────────────
app.use('/api/vulnerable', createVulnerableRouter(getDB, sessions));
app.use('/api/safe', createSafeRouter(getDB, sessions));

// ── Session Info Endpoint ────────────────────────────────────────────────
app.get('/api/session', (req, res) => {
  const sid = req.cookies?.session_id;
  if (sid && sessions.has(sid)) {
    const s = sessions.get(sid);
    // Refresh balance from DB
    const db = getDB();
    db.query('SELECT balance, email FROM users WHERE username = $1', [s.username])
      .then(result => {
        if (result.rows.length > 0) {
          s.balance = result.rows[0].balance;
          s.email = result.rows[0].email;
        }
        res.json({
          loggedIn: true,
          user: {
            id: s.userId,
            username: s.username,
            fullName: s.fullName,
            email: s.email,
            role: s.role,
            balance: s.balance,
          },
          csrfToken: s.csrfToken || null,
        });
      })
      .catch(() => {
        res.json({ loggedIn: true, user: { ...s }, csrfToken: s.csrfToken || null });
      });
  } else {
    res.json({ loggedIn: false });
  }
});

// ── Logout ───────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  const sid = req.cookies?.session_id;
  if (sid) sessions.delete(sid);
  res.clearCookie('session_id', { path: '/' });
  res.json({ success: true, message: 'Logged out successfully.' });
});

// ── Reset Database ───────────────────────────────────────────────────────
app.post('/api/reset-db', async (_req, res) => {
  try {
    await resetDatabase();
    // Clear all sessions (since user data has been reset)
    sessions.clear();
    res.json({ success: true, message: 'Database reset and re-seeded successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── SPA Fallback: serve index.html for all non-API routes ────────────────
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// ── Start Server ─────────────────────────────────────────────────────────
async function startServer() {
  console.log('\n╔═══════════════════════════════════════════════════════════╗');
  console.log('║      🏦 SentinelBank — Web Security Lab Server          ║');
  console.log('╚═══════════════════════════════════════════════════════════╝\n');

  console.log('  ⏳ Initializing embedded PostgreSQL (PGlite)...');
  await initDatabase();

  app.listen(PORT, () => {
    console.log(`\n  🚀 SentinelBank running at:  http://localhost:${PORT}`);
    console.log('  📡 Vulnerable API:           /api/vulnerable/*');
    console.log('  🛡️  Safe API:                 /api/safe/*');
    console.log('  🔄 Reset DB:                 POST /api/reset-db');
    console.log('\n  ⚠️  Start the attacker server separately:');
    console.log('     node attacker-server.js   →  http://localhost:5500\n');
  });
}

startServer().catch(err => {
  console.error('❌ Failed to start server:', err);
  process.exit(1);
});

