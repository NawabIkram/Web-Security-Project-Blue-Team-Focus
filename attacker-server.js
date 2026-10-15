// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║  Attacker Server — Simulates a malicious third-party site (port 5500)  ║
// ║  Serves the CSRF exploit page at http://localhost:5500/csrf-exploit.html║
// ╚═══════════════════════════════════════════════════════════════════════════╝

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 5500;

// Serve the attacker's static files
app.use(express.static(path.join(__dirname, 'attacker')));

app.get('/', (_req, res) => {
  res.redirect('/csrf-exploit.html');
});

app.listen(PORT, () => {
  console.log(`\n  🔴 Attacker server running at: http://localhost:${PORT}`);
  console.log(`  🎯 CSRF exploit page:          http://localhost:${PORT}/csrf-exploit.html\n`);
});

