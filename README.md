# 🏦 SentinelBank — Web Security Lab

> **Information Security Practical Assignment 2 — Part 2: Web Security Project (Blue Team Focus)**

A complete, production-looking, database-driven full-stack web application demonstrating real web vulnerabilities (XSS, CSRF, SQL Injection) and their industry-standard mitigations.

---

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [Database Schema](#database-schema)
- [Vulnerability Summary](#vulnerability-summary)
- [Project Structure](#project-structure)
- [How to Demo (Viva)](#how-to-demo-viva)

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         BROWSER                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  SentinelBank Frontend (Tailwind + Vanilla JS SPA)      │   │
│  │  • Mode Toggle: 🔴 Vulnerable ←→ 🟢 Safe               │   │
│  │  • DOM-Based XSS: reads window.location.hash            │   │
│  └─────────────────────┬───────────────────────────────────┘   │
│                        │ fetch() with credentials               │
├────────────────────────┼────────────────────────────────────────┤
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Express Server (port 5000)                              │   │
│  │  ├── /api/vulnerable/*  (string concat, no CSRF, etc.)  │   │
│  │  ├── /api/safe/*        (parameterized, CSRF tokens)     │   │
│  │  ├── /api/session       (session check)                  │   │
│  │  └── /api/reset-db      (reset all data)                 │   │
│  └─────────────────────┬───────────────────────────────────┘   │
│                        │                                        │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  @electric-sql/pglite (Embedded PostgreSQL via WASM)     │   │
│  │  • Real SQL engine with information_schema support        │   │
│  │  • Persisted to ./pgdata/                                 │   │
│  │  • Tables: users, staff_directory, transactions,          │   │
│  │    feedback_reviews, audit_secrets                         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Attacker Server (port 5500) — Malicious third-party     │   │
│  │  └── csrf-exploit.html (hidden form auto-submit)         │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Tech Stack

| Component | Technology |
|---|---|
| **Backend** | Node.js + Express (port 5000) |
| **Database** | `@electric-sql/pglite` — Embedded PostgreSQL (WASM) |
| **Frontend** | HTML5 + Tailwind CSS (CDN) + Vanilla JavaScript |
| **Sessions** | In-memory Map + `cookie-parser` |
| **CSRF Demo** | Attacker Express server on port 5500 |
| **Package Manager** | npm |

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Start the main SentinelBank server (port 5000)
node server.js

# 3. In a separate terminal, start the attacker server (port 5500)
node attacker-server.js

# 4. Open the application
open http://localhost:5000

# 5. (Optional) Run the automated verification suite
node verify-exploits.js
```

### Test Accounts

| Username | Password | Role | Balance |
|---|---|---|---|
| `admin` | `SuperSecretAdmin#2026` | Administrator | $950,000 |
| `alice` | `AliceBank123` | Premium Customer | $42,500 |
| `bob` | `BobSecure99` | Customer | $18,200 |
| `charlie` | `CharliePass456` | Customer | $8,750 |
| `diana` | `DianaWelcome1` | VIP Customer | $31,200 |

---

## 🗄️ Database Schema

| Table | Purpose | Columns |
|---|---|---|
| `users` | Customer accounts | id, username, password, full_name, email, role, balance |
| `staff_directory` | Bank staff (all TEXT for UNION compat) | staff_code, full_name, department, branch_city, contact_email |
| `transactions` | Transfer history | id (SERIAL), sender, recipient, amount, note, created_at |
| `feedback_reviews` | Customer reviews (Stored XSS) | id (SERIAL), author, rating, comment, created_at |
| `audit_secrets` | High-value secrets (SQLi target) | secret_id, vault_key, recovery_pin |

---

## 🔓 Vulnerability Summary

| # | Vulnerability | Endpoint | Vulnerable Code | Safe Defense |
|---|---|---|---|---|
| 1 | **SQLi L1: Auth Bypass** | `POST /api/{mode}/login` | String concatenation in WHERE clause | Parameterized queries (`$1, $2`) |
| 2 | **SQLi L2: Blind Boolean** | `GET /api/{mode}/verify-account` | String concat enables AND SUBSTRING() | Parameterized `WHERE username = $1` |
| 3 | **SQLi L3: UNION Injection** | `GET /api/{mode}/staff` | String concat in LIKE with 4 TEXT cols | Parameterized `LIKE $1` |
| 4 | **XSS Reflected** | `GET /api/{mode}/search-payee` | Raw query reflected in HTML | HTML entity encoding + textContent |
| 5 | **XSS Stored** | `GET/POST /api/{mode}/reviews` | Raw HTML stored & rendered via innerHTML | Server-side encoding + textContent |
| 6 | **XSS DOM-Based** | Client-side (`location.hash`) | innerHTML from hash without validation | Allowlist + textContent |
| 7 | **CSRF** | `POST /api/{mode}/transfer`, `/update-email` | No token, no origin check | Synchronizer CSRF Token + Origin validation |

---

## 📁 Project Structure

```
is2/
├── package.json              # Dependencies & scripts
├── server.js                 # Main Express server (port 5000)
├── attacker-server.js        # Malicious server (port 5500)
├── verify-exploits.js        # Automated test suite
├── db/
│   └── init.js               # PGlite setup, schema, & seed data
├── backend/
│   └── routes/
│       ├── vulnerable.js     # All vulnerable endpoints
│       └── safe.js           # All hardened endpoints
├── frontend/
│   └── index.html            # Complete SPA dashboard
├── attacker/
│   └── csrf-exploit.html     # CSRF attack page
├── README.md                 # This file
├── VIVA_AND_REPORT_GUIDE.md  # Detailed viva & report guide
└── pgdata/                   # PGlite persistent data (auto-created)
```

---

## 🎤 How to Demo (Viva)

1. Start both servers (`node server.js` + `node attacker-server.js`)
2. Open `http://localhost:5000` in your browser
3. Use the **Mode Toggle** in the navbar to switch between Vulnerable and Safe modes
4. For each vulnerability, demonstrate it in Vulnerable mode, then switch to Safe mode to show it's blocked
5. Use the **Reset DB** button between demonstrations to restore clean data
6. Refer to `VIVA_AND_REPORT_GUIDE.md` for exact payloads and expected results

---

## 📄 License

MIT — For educational purposes only.

