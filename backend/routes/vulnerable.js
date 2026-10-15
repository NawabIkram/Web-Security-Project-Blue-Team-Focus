// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  VULNERABLE ROUTES — Every endpoint intentionally contains real flaws   ║
// ║  SQL Injection (string concatenation), XSS (no encoding), CSRF (none)   ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

import { Router } from 'express';
import crypto from 'crypto';

export function createVulnerableRouter(getDB, sessions) {
  const router = Router();

  // ── Helper: require authentication ──────────────────────────────────────
  function requireAuth(req, res, next) {
    const sid = req.cookies?.session_id;
    if (!sid || !sessions.has(sid)) {
      return res.status(401).json({ success: false, message: 'Not authenticated. Please log in.' });
    }
    req.userSession = sessions.get(sid);
    req.sessionId = sid;
    next();
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 1. SQL INJECTION — LEVEL 1: Login Authentication Bypass
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // VULNERABLE: Raw string concatenation in SQL query.
  // Payload:  username = admin' --    password = anything
  //       or  username = ' OR '1'='1' --
  router.post('/login', async (req, res) => {
    const db = getDB();
    const { username, password } = req.body;

    // ⚠️ VULNERABLE: Direct string interpolation — classic SQL injection
    const query = `SELECT id, username, full_name, email, role, balance FROM users WHERE username = '${username}' AND password = '${password}'`;

    try {
      const result = await db.query(query);

      if (result.rows.length > 0) {
        const user = result.rows[0];
        const sessionId = crypto.randomUUID();
        sessions.set(sessionId, {
          userId: user.id,
          username: user.username,
          fullName: user.full_name,
          email: user.email,
          role: user.role,
          balance: user.balance,
        });

        // ⚠️ VULNERABLE: httpOnly false allows JS to read cookie (for XSS cookie theft demo)
        res.cookie('session_id', sessionId, {
          httpOnly: false,
          sameSite: 'lax',
          path: '/',
          maxAge: 3600000,
        });

        return res.json({
          success: true,
          message: `Welcome back, ${user.full_name}!`,
          user: {
            id: user.id,
            username: user.username,
            fullName: user.full_name,
            email: user.email,
            role: user.role,
            balance: user.balance,
          },
          queryLog: query,
        });
      } else {
        return res.json({
          success: false,
          message: 'Invalid username or password.',
          queryLog: query,
        });
      }
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: `Database error: ${err.message}`,
        queryLog: query,
      });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 2. XSS — REFLECTED: Payee / Transaction Search
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // VULNERABLE: Raw query parameter reflected back in HTML without encoding.
  // Payload:  q=<img src=x onerror=alert('Reflected_XSS_Executed')>
  router.get('/search-payee', async (req, res) => {
    const db = getDB();
    const q = req.query.q || '';

    // ⚠️ VULNERABLE: q is embedded raw into HTML — reflected XSS
    const html = `<div class="search-result-banner">
      <p class="text-lg">Search results for: <strong>${q}</strong></p>
    </div>`;

    let results = [];
    try {
      // Also run an actual DB search (also injectable, but primary vuln is XSS)
      const dbQuery = `SELECT username, full_name, email FROM users WHERE username LIKE '%${q}%' OR full_name LIKE '%${q}%'`;
      const result = await db.query(dbQuery);
      results = result.rows;
    } catch (_) {
      // Ignore DB errors for XSS demo
    }

    res.json({ html, query: q, results });
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 3. XSS — STORED: Customer Feedback / Review Wall
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // GET:  Returns all reviews (raw HTML in comment field)
  // POST: Stores user comment without any sanitization
  router.get('/reviews', async (_req, res) => {
    const db = getDB();
    try {
      const result = await db.query('SELECT id, author, rating, comment, created_at FROM feedback_reviews ORDER BY id DESC');
      res.json({ success: true, reviews: result.rows });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  });

  router.post('/reviews', requireAuth, async (req, res) => {
    const db = getDB();
    const { comment, rating } = req.body;
    const author = req.userSession.username;
    const created_at = new Date().toISOString();

    try {
      // ⚠️ VULNERABLE: Raw HTML/JS stored in DB without sanitization.
      // Parameterized INSERT used to avoid SQL errors from special chars,
      // but no HTML encoding — the XSS is in the rendering, not the storage mechanism.
      await db.query(
        'INSERT INTO feedback_reviews (author, rating, comment, created_at) VALUES ($1, $2, $3, $4)',
        [author, parseInt(rating) || 5, comment, created_at]
      );
      res.json({ success: true, message: 'Review posted successfully!' });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 4. CSRF — Wire Transfer (no token, no origin check)
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // VULNERABLE: No CSRF token verification. Accepts form-encoded POST from any origin.
  router.post('/transfer', requireAuth, async (req, res) => {
    const db = getDB();
    const session = req.userSession;
    const { recipient, amount, note } = req.body;
    const transferAmount = parseInt(amount);

    if (!recipient || !transferAmount || transferAmount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid transfer details.' });
    }

    if (transferAmount > session.balance) {
      return res.status(400).json({ success: false, message: 'Insufficient funds.' });
    }

    try {
      // Check recipient exists
      const recipientResult = await db.query('SELECT username, balance FROM users WHERE username = $1', [recipient]);
      if (recipientResult.rows.length === 0) {
        return res.status(404).json({ success: false, message: `Recipient '${recipient}' not found.` });
      }

      // Deduct from sender
      await db.query('UPDATE users SET balance = balance - $1 WHERE username = $2', [transferAmount, session.username]);
      // Credit recipient
      await db.query('UPDATE users SET balance = balance + $1 WHERE username = $2', [transferAmount, recipient]);
      // Record transaction
      await db.query(
        'INSERT INTO transactions (sender, recipient, amount, note, created_at) VALUES ($1, $2, $3, $4, $5)',
        [session.username, recipient, transferAmount, note || '', new Date().toISOString()]
      );

      // Update session balance
      session.balance -= transferAmount;

      res.json({
        success: true,
        message: `✅ Successfully transferred $${transferAmount.toLocaleString()} to ${recipient}`,
        newBalance: session.balance,
      });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 5. CSRF — Update Email (no token, no origin check)
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  router.post('/update-email', requireAuth, async (req, res) => {
    const db = getDB();
    const session = req.userSession;
    const { newEmail } = req.body;

    if (!newEmail) {
      return res.status(400).json({ success: false, message: 'Email address is required.' });
    }

    try {
      await db.query('UPDATE users SET email = $1 WHERE username = $2', [newEmail, session.username]);
      session.email = newEmail;
      res.json({ success: true, message: `Email updated to ${newEmail}` });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 6. SQL INJECTION — LEVEL 2: Blind Boolean & Error-Based
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // VULNERABLE: String concatenation enabling boolean-based blind injection
  //   and error-based extraction via CAST.
  // Payload (boolean): admin' AND SUBSTRING(password, 1, 1) = 'S' --
  // Payload (error):   admin' AND 1=CAST((SELECT password FROM users WHERE username='admin') AS INT) --
  router.get('/verify-account', async (req, res) => {
    const db = getDB();
    const username = req.query.username || '';

    // ⚠️ VULNERABLE: Direct string concatenation
    const query = `SELECT username, role FROM users WHERE username = '${username}'`;

    try {
      const result = await db.query(query);

      if (result.rows.length > 0) {
        return res.json({
          status: 'active',
          message: '✅ Account Active & Verified',
          data: { username: result.rows[0].username, role: result.rows[0].role },
          queryLog: query,
        });
      } else {
        return res.json({
          status: 'not_found',
          message: '❌ Account Not Found',
          queryLog: query,
        });
      }
    } catch (err) {
      // ⚠️ VULNERABLE: Exposes raw database error messages (enables error-based SQLi)
      return res.status(500).json({
        status: 'error',
        message: `Database Error: ${err.message}`,
        queryLog: query,
      });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 7. SQL INJECTION — LEVEL 3: Advanced UNION-Based (4-Stage Attack Chain)
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // VULNERABLE: String concatenation in LIKE clause with 4 TEXT columns.
  //
  // Stage 1: %' ORDER BY 4 --         (succeeds, confirms 4 columns)
  //          %' ORDER BY 5 --         (fails, proves only 4 columns)
  // Stage 2: %' UNION SELECT table_schema, table_name, table_type, '4'
  //          FROM information_schema.tables WHERE table_schema = 'public' --
  // Stage 3: %' UNION SELECT table_name, column_name, data_type, '4'
  //          FROM information_schema.columns WHERE table_name = 'users' --
  // Stage 4: %' UNION SELECT username, password, email,
  //          role || ' ($' || balance::text || ')' FROM users --
  router.get('/staff', async (req, res) => {
    const db = getDB();
    const dept = req.query.dept || '';

    // ⚠️ VULNERABLE: Direct string concatenation — full UNION injection possible
    const query = `SELECT staff_code, full_name, department, contact_email FROM staff_directory WHERE department LIKE '%${dept}%'`;

    try {
      const result = await db.query(query);
      res.json({
        success: true,
        query: query,
        results: result.rows,
      });
    } catch (err) {
      res.status(500).json({
        success: false,
        message: `Database Error: ${err.message}`,
        query: query,
      });
    }
  });

  // ── Transaction History ──────────────────────────────────────────────────
  router.get('/transactions', requireAuth, async (req, res) => {
    const db = getDB();
    const session = req.userSession;
    try {
      const result = await db.query(
        'SELECT id, sender, recipient, amount, note, created_at FROM transactions WHERE sender = $1 OR recipient = $1 ORDER BY id DESC',
        [session.username]
      );
      res.json({ success: true, transactions: result.rows });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  });

  return router;
}

