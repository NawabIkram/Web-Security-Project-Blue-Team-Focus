// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  SAFE (HARDENED) ROUTES — Every vulnerability from vulnerable.js is     ║
// ║  properly mitigated with industry-standard defenses.                    ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

import { Router } from 'express';
import crypto from 'crypto';

// ── HTML Entity Encoder (server-side output encoding) ────────────────────
function escapeHTML(str) {
  if (typeof str !== 'string') return String(str);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

export function createSafeRouter(getDB, sessions) {
  const router = Router();

  // ── CSP middleware — applied to all safe-mode responses ─────────────────
  router.use((_req, res, next) => {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net; connect-src 'self'"
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    next();
  });

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

  // ── Helper: CSRF token verification ─────────────────────────────────────
  function csrfProtect(req, res, next) {
    const sid = req.cookies?.session_id;
    const session = sessions.get(sid);
    if (!session) {
      return res.status(401).json({ success: false, message: 'Not authenticated.' });
    }

    const token = req.headers['x-csrf-token'] || req.body?._csrf;
    if (!token || token !== session.csrfToken) {
      return res.status(403).json({
        success: false,
        message: '403 Forbidden: Invalid or Missing CSRF Token',
      });
    }

    // Additional: Validate Origin header
    const origin = req.headers.origin || req.headers.referer || '';
    const allowedOrigin = 'http://localhost:5000';
    if (origin && !origin.startsWith(allowedOrigin)) {
      return res.status(403).json({
        success: false,
        message: '403 Forbidden: Origin validation failed — request origin does not match the application.',
      });
    }

    req.userSession = session;
    req.sessionId = sid;
    next();
  }

  // ── Input validation: alphanumeric + limited special chars ──────────────
  function sanitizeInput(str, maxLen = 200) {
    if (typeof str !== 'string') return '';
    return str.slice(0, maxLen).replace(/[^\w\s@.\-#]/g, '');
  }

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 1. SQL INJECTION FIX — Login with Parameterized Queries
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // SAFE: Uses $1, $2 parameterized query — injection payloads are treated
  // as literal strings and fail authentication.
  router.post('/login', async (req, res) => {
    const db = getDB();
    const { username, password } = req.body;

    // ✅ SAFE: Parameterized query prevents SQL injection
    const query = 'SELECT id, username, full_name, email, role, balance FROM users WHERE username = $1 AND password = $2';
    const queryLog = `SELECT id, username, full_name, email, role, balance FROM users WHERE username = '${escapeHTML(username)}' AND password = '***'`;

    try {
      const result = await db.query(query, [username, password]);

      if (result.rows.length > 0) {
        const user = result.rows[0];
        const sessionId = crypto.randomUUID();
        const csrfToken = crypto.randomUUID();

        sessions.set(sessionId, {
          userId: user.id,
          username: user.username,
          fullName: user.full_name,
          email: user.email,
          role: user.role,
          balance: user.balance,
          csrfToken,
        });

        // ✅ SAFE: httpOnly=true prevents JS access, sameSite=strict adds CSRF layer
        res.cookie('session_id', sessionId, {
          httpOnly: true,
          sameSite: 'strict',
          path: '/',
          maxAge: 3600000,
        });

        return res.json({
          success: true,
          message: `Welcome back, ${escapeHTML(user.full_name)}!`,
          user: {
            id: user.id,
            username: user.username,
            fullName: user.full_name,
            email: user.email,
            role: user.role,
            balance: user.balance,
          },
          csrfToken,
          queryLog,
        });
      } else {
        // ✅ SAFE: Generic error message — doesn't reveal whether username exists
        return res.json({
          success: false,
          message: 'Invalid username or password.',
          queryLog,
        });
      }
    } catch (err) {
      // ✅ SAFE: Generic error — no raw DB errors leaked
      return res.status(500).json({
        success: false,
        message: 'An internal error occurred. Please try again later.',
        queryLog,
      });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 2. XSS FIX — Reflected: Payee Search with Output Encoding
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // SAFE: HTML-encodes the query on the server side + client uses textContent.
  router.get('/search-payee', async (req, res) => {
    const db = getDB();
    const q = req.query.q || '';

    // ✅ SAFE: Validate & sanitize input, HTML-encode output
    const safeQ = sanitizeInput(q, 100);
    const encodedQ = escapeHTML(safeQ);

    const html = `<div class="search-result-banner">
      <p class="text-lg">Search results for: <strong>${encodedQ}</strong></p>
    </div>`;

    let results = [];
    try {
      // ✅ SAFE: Parameterized query
      const result = await db.query(
        'SELECT username, full_name, email FROM users WHERE username LIKE $1 OR full_name LIKE $1',
        [`%${safeQ}%`]
      );
      results = result.rows;
    } catch (_) {
      // silently fail
    }

    res.json({ html, query: encodedQ, results, safe: true });
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 3. XSS FIX — Stored: Reviews with Output Encoding
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // SAFE: HTML-encodes comments on output so stored scripts render as text.
  router.get('/reviews', async (_req, res) => {
    const db = getDB();
    try {
      const result = await db.query('SELECT id, author, rating, comment, created_at FROM feedback_reviews ORDER BY id DESC');
      // ✅ SAFE: Encode every comment before sending to client
      const safeReviews = result.rows.map(r => ({
        ...r,
        comment: escapeHTML(r.comment),
        author: escapeHTML(r.author),
      }));
      res.json({ success: true, reviews: safeReviews, safe: true });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Failed to load reviews.' });
    }
  });

  router.post('/reviews', requireAuth, async (req, res) => {
    const db = getDB();
    const { comment, rating } = req.body;
    const author = req.userSession.username;
    const created_at = new Date().toISOString();

    // ✅ SAFE: Validate rating, sanitize comment before storage
    const safeRating = Math.min(5, Math.max(1, parseInt(rating) || 5));
    const safeComment = escapeHTML(comment || '');

    try {
      await db.query(
        'INSERT INTO feedback_reviews (author, rating, comment, created_at) VALUES ($1, $2, $3, $4)',
        [author, safeRating, safeComment, created_at]
      );
      res.json({ success: true, message: 'Review posted successfully!' });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Failed to post review.' });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 4. CSRF FIX — Wire Transfer with Synchronizer Token Pattern
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // SAFE: Requires valid X-CSRF-Token header + Origin validation.
  router.post('/transfer', csrfProtect, async (req, res) => {
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
      const recipientResult = await db.query('SELECT username, balance FROM users WHERE username = $1', [recipient]);
      if (recipientResult.rows.length === 0) {
        return res.status(404).json({ success: false, message: `Recipient '${escapeHTML(recipient)}' not found.` });
      }

      await db.query('UPDATE users SET balance = balance - $1 WHERE username = $2', [transferAmount, session.username]);
      await db.query('UPDATE users SET balance = balance + $1 WHERE username = $2', [transferAmount, recipient]);
      await db.query(
        'INSERT INTO transactions (sender, recipient, amount, note, created_at) VALUES ($1, $2, $3, $4, $5)',
        [session.username, recipient, transferAmount, note || '', new Date().toISOString()]
      );

      session.balance -= transferAmount;

      res.json({
        success: true,
        message: `✅ Successfully transferred $${transferAmount.toLocaleString()} to ${escapeHTML(recipient)}`,
        newBalance: session.balance,
      });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Transfer failed. Please try again.' });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 5. CSRF FIX — Update Email with Synchronizer Token Pattern
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  router.post('/update-email', csrfProtect, async (req, res) => {
    const db = getDB();
    const session = req.userSession;
    const { newEmail } = req.body;

    if (!newEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
      return res.status(400).json({ success: false, message: 'Invalid email address format.' });
    }

    try {
      await db.query('UPDATE users SET email = $1 WHERE username = $2', [newEmail, session.username]);
      session.email = newEmail;
      res.json({ success: true, message: `Email updated to ${escapeHTML(newEmail)}` });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Failed to update email.' });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 6. SQL INJECTION FIX — Blind Boolean/Error-Based with Parameterized Query
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // SAFE: Parameterized query + generic error messages block all inference.
  router.get('/verify-account', async (req, res) => {
    const db = getDB();
    const username = req.query.username || '';

    // ✅ SAFE: Parameterized query
    const query = 'SELECT username, role FROM users WHERE username = $1';
    const queryLog = `SELECT username, role FROM users WHERE username = '${escapeHTML(username)}'`;

    try {
      const result = await db.query(query, [username]);

      if (result.rows.length > 0) {
        return res.json({
          status: 'active',
          message: '✅ Account Active & Verified',
          data: { username: result.rows[0].username, role: result.rows[0].role },
          queryLog,
        });
      } else {
        return res.json({
          status: 'not_found',
          message: '❌ Account Not Found',
          queryLog,
        });
      }
    } catch (_err) {
      // ✅ SAFE: Generic error — no DB error details leaked
      return res.status(500).json({
        status: 'error',
        message: 'An internal error occurred.',
        queryLog,
      });
    }
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 7. SQL INJECTION FIX — Advanced UNION-Based with Parameterized LIKE
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // SAFE: Uses WHERE department LIKE $1 with ['%' + dept + '%'].
  // The entire UNION SELECT payload becomes a literal search string → 0 rows.
  router.get('/staff', async (req, res) => {
    const db = getDB();
    const dept = req.query.dept || '';

    // ✅ SAFE: Parameterized query — UNION payloads are treated as literal text
    const query = 'SELECT staff_code, full_name, department, contact_email FROM staff_directory WHERE department LIKE $1';
    const param = `%${dept}%`;
    const queryLog = `SELECT staff_code, full_name, department, contact_email FROM staff_directory WHERE department LIKE '%${escapeHTML(dept)}%'`;

    try {
      const result = await db.query(query, [param]);
      res.json({
        success: true,
        query: queryLog,
        results: result.rows,
        safe: true,
      });
    } catch (_err) {
      res.status(500).json({
        success: false,
        message: 'An internal error occurred.',
        query: queryLog,
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
    } catch (_err) {
      res.status(500).json({ success: false, message: 'Failed to load transactions.' });
    }
  });

  // ── CSRF Token endpoint ─────────────────────────────────────────────────
  router.get('/csrf-token', requireAuth, (req, res) => {
    res.json({ csrfToken: req.userSession.csrfToken });
  });

  return router;
}

