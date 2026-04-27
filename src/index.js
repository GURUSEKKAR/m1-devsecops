const express = require('express');

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

// ✅ Security headers
app.use(helmet());

// ✅ Rate limiting (protect login, APIs)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// ✅ Move secrets to env variables
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';

// ✅ Hash password (for demo using sha256)
const hash = (pwd) => crypto.createHash('sha256').update(pwd).digest('hex');

// In-memory DB
let users = [
  { id: 1, username: 'admin', password: hash('admin123'), role: 'admin' },
  { id: 2, username: 'user1', password: hash('password'), role: 'user' }
];

let messages = [];

// ==================== HELPERS ====================

// ✅ Auth middleware
function authenticate(req, res, next) {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).send('Unauthorized');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).send('Invalid token');
  }
}

// ==================== ROUTES ====================

// Home
app.get('/', (req, res) => {
  res.send(`<h1>Secure M1 App</h1><a href="/login">Login</a>`);
});

// ✅ FIXED XSS using escape
function escapeHTML(str) {
  return str.replace(/[&<>"']/g, (char) => {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return map[char];
  });
}

app.get('/search', (req, res) => {
  const query = escapeHTML(req.query.q || '');
  res.send(`<h2>Search: ${query}</h2>`);
});

// Login page
app.get('/login', (req, res) => {
  res.send(`
    <form method="POST">
      <input name="username" required />
      <input name="password" type="password" required />
      <button>Login</button>
    </form>
  `);
});

// ✅ Secure login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const hashed = hash(password);

  const user = users.find(u => u.username === username && u.password === hashed);

  if (!user) return res.status(401).send('Invalid credentials');

  const token = jwt.sign(
    { id: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict'
  });

  res.send('Login success');
});

// ✅ FIXED IDOR + no password exposure
app.get('/profile/:id', authenticate, (req, res) => {
  if (req.user.id !== parseInt(req.params.id)) {
    return res.status(403).send('Forbidden');
  }

  const user = users.find(u => u.id === req.user.id);

  res.json({
    id: user.id,
    username: user.username,
    role: user.role
  });
});

// ✅ FIXED Stored XSS
app.post('/messages', authenticate, (req, res) => {
  const text = escapeHTML(req.body.text);
  messages.push({
    user: req.user.id,
    text,
    time: new Date()
  });
  res.send('Message added');
});

// ✅ FIXED command injection (no exec)
app.get('/api/ping', (req, res) => {
  res.send('Ping disabled for security');
});

// ✅ FIXED path traversal
app.get('/api/file', (req, res) => {
  const filename = path.basename(req.query.name);
  const filepath = path.join(__dirname, 'uploads', filename);
  res.sendFile(filepath);
});

// ✅ REMOVE debug endpoint or restrict
app.get('/debug', (req, res) => {
  res.status(403).send('Disabled');
});

// ✅ FIXED open redirect
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  if (!url.startsWith('/')) return res.status(400).send('Invalid URL');
  res.redirect(url);
});

// ✅ REMOVE eval
app.post('/api/calculate', (req, res) => {
  res.status(400).send('Disabled');
});

// ✅ Secure token generation
app.get('/api/token', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  res.json({ token });
});

// Health
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// ✅ Safe error handler
app.use((err, req, res, next) => {
  res.status(500).json({ error: 'Internal Server Error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Secure App running on ${PORT}`);
});


// {
//   "name": "m1-secure-app",
//   "version": "1.0.2",
//   "description": "M1 DevSecOps Secure Application",
//   "main": "index.js",
//   "scripts": {
//     "start": "node index.js",
//     "test": "echo \"No tests configured\""
//   },
//   "dependencies": {
//     "body-parser":        "1.20.3",
//     "cookie-parser":      "1.4.7",
//     "express":            "4.21.2",
//     "express-rate-limit": "7.4.0",
//     "helmet":             "8.0.0",
//     "jsonwebtoken":       "9.0.2"
//   },
//   "overrides": {
//     "path-to-regexp": "0.1.13",
//     "qs":             "6.13.0"
//   }
// }




// // ============================================================
// // M1 DevSecOps - Intentionally Vulnerable Test Application
// // ============================================================
// // This file contains DELIBERATE security flaws to validate that
// // the pipeline scanners (Trivy, OWASP DC, SonarQube, ZAP) all
// // detect what they are supposed to detect.
// //
// // DO NOT DEPLOY THIS TO PRODUCTION. It is a test harness only.
// // ============================================================

// const express = require('express');
// const fs = require('fs');
// const path = require('path');
// const { exec } = require('child_process');
// const crypto = require('crypto');
// const jwt = require('jsonwebtoken');
// const _ = require('lodash');
// const axios = require('axios');

// const app = express();
// app.use(express.json());
// app.use(express.urlencoded({ extended: true }));

// // ------------------------------------------------------------
// // VULN 1: Hardcoded credentials and secrets
// // SonarQube rule: javascript:S2068 (hard-coded credentials)
// // ------------------------------------------------------------
// const DB_PASSWORD = "SuperSecret123!";
// const API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
// const JWT_SECRET = "hardcoded-jwt-secret-do-not-use";
// const AWS_SECRET = "AKIAIOSFODNN7EXAMPLE";

// // ------------------------------------------------------------
// // VULN 2: Weak cryptography (MD5)
// // SonarQube rule: javascript:S4790 (weak hashing)
// // ------------------------------------------------------------
// function hashPassword(password) {
//     return crypto.createHash('md5').update(password).digest('hex');
// }

// // ------------------------------------------------------------
// // VULN 3: Insecure random for security tokens
// // SonarQube rule: javascript:S2245 (Math.random for security)
// // ------------------------------------------------------------
// function generateSessionToken() {
//     return Math.random().toString(36).substring(2);
// }

// // ------------------------------------------------------------
// // HEALTH endpoint - required by Jenkinsfile Stage 6
// // ------------------------------------------------------------
// app.get('/health', (req, res) => {
//     res.status(200).json({ status: 'ok', uptime: process.uptime() });
// });

// // ------------------------------------------------------------
// // Home page - intentionally NO security headers
// // ZAP will flag: missing CSP, X-Frame-Options, X-Content-Type-Options,
// // Strict-Transport-Security, Referrer-Policy
// // ------------------------------------------------------------
// app.get('/', (req, res) => {
//     res.send(`
//         <html>
//             <head><title>M1 Vulnerable Test App</title></head>
//             <body>
//                 <h1>M1 DevSecOps Test Application</h1>
//                 <p>Intentionally vulnerable - DO NOT use in production.</p>
//                 <ul>
//                     <li>GET  /health</li>
//                     <li>GET  /search?q=...</li>
//                     <li>GET  /file?name=...</li>
//                     <li>POST /login</li>
//                     <li>GET  /redirect?url=...</li>
//                     <li>GET  /ping?host=...</li>
//                     <li>GET  /fetch?url=...</li>
//                     <li>GET  /eval?code=...</li>
//                 </ul>
//             </body>
//         </html>
//     `);
// });

// // ------------------------------------------------------------
// // VULN 4: SQL injection via string concatenation
// // SonarQube rule: javascript:S3649
// // (We don't actually run a DB - the dangerous pattern is what's scanned)
// // ------------------------------------------------------------
// app.get('/search', (req, res) => {
//     const userInput = req.query.q || '';
//     // BAD: query built by concatenation
//     const query = "SELECT * FROM products WHERE name LIKE '%" + userInput + "%'";
//     console.log("Executing query: " + query);
//     res.json({ query: query, results: [] });
// });

// // ------------------------------------------------------------
// // VULN 5: Path traversal / arbitrary file read
// // SonarQube rule: javascript:S2083
// // ------------------------------------------------------------
// app.get('/file', (req, res) => {
//     const fileName = req.query.name || 'default.txt';
//     // BAD: user input concatenated into path with no sanitization
//     const filePath = path.join(__dirname, 'public', fileName);
//     fs.readFile(filePath, 'utf8', (err, data) => {
//         if (err) return res.status(404).send('Not found');
//         res.send(data);
//     });
// });

// // ------------------------------------------------------------
// // VULN 6: Command injection
// // SonarQube rule: javascript:S2076
// // ------------------------------------------------------------
// app.get('/ping', (req, res) => {
//     const host = req.query.host || 'localhost';
//     // BAD: user input passed straight into shell
//     exec('ping -c 1 ' + host, (err, stdout, stderr) => {
//         if (err) return res.status(500).send(stderr);
//         res.send('<pre>' + stdout + '</pre>');
//     });
// });

// // ------------------------------------------------------------
// // VULN 7: Open redirect
// // SonarQube rule: javascript:S5146
// // ------------------------------------------------------------
// app.get('/redirect', (req, res) => {
//     const url = req.query.url;
//     // BAD: redirects anywhere the attacker wants
//     res.redirect(url);
// });

// // ------------------------------------------------------------
// // VULN 8: Server-Side Request Forgery (SSRF)
// // SonarQube rule: javascript:S6105
// // ------------------------------------------------------------
// app.get('/fetch', async (req, res) => {
//     const url = req.query.url;
//     try {
//         // BAD: fetches any URL, including internal AWS metadata 169.254.169.254
//         const response = await axios.get(url);
//         res.send(response.data);
//     } catch (e) {
//         res.status(500).send(e.message);
//     }
// });

// // ------------------------------------------------------------
// // VULN 9: Code injection via eval
// // SonarQube rule: javascript:S1523
// // ------------------------------------------------------------
// app.get('/eval', (req, res) => {
//     const code = req.query.code || '1+1';
//     // BAD: eval on user input
//     const result = eval(code);
//     res.json({ result: result });
// });

// // ------------------------------------------------------------
// // VULN 10: XSS via reflected user input
// // SonarQube rule: javascript:S5247
// // ------------------------------------------------------------
// app.get('/greet', (req, res) => {
//     const name = req.query.name || 'guest';
//     // BAD: user input written to HTML without escaping
//     res.send('<h1>Hello, ' + name + '!</h1>');
// });

// // ------------------------------------------------------------
// // VULN 11: Weak JWT verification (no algorithm enforcement)
// // + Hardcoded JWT secret
// // SonarQube rule: javascript:S5659
// // ------------------------------------------------------------
// app.post('/login', (req, res) => {
//     const { username, password } = req.body || {};
//     // BAD: MD5 password hashing
//     const hashed = hashPassword(password || '');
//     // BAD: hardcoded secret + no algorithm restriction
//     const token = jwt.sign({ user: username, role: 'admin' }, JWT_SECRET);
//     res.json({ token: token, hash: hashed, sessionId: generateSessionToken() });
// });

// app.get('/profile', (req, res) => {
//     const auth = req.headers.authorization || '';
//     const token = auth.replace('Bearer ', '');
//     try {
//         // BAD: no algorithm whitelist - allows "none" algorithm attack
//         const decoded = jwt.verify(token, JWT_SECRET);
//         res.json({ profile: decoded });
//     } catch (e) {
//         res.status(401).send('Invalid token');
//     }
// });

// // ------------------------------------------------------------
// // VULN 12: Prototype pollution via lodash.merge (uses old lodash)
// // SonarQube rule: javascript:S6479
// // ------------------------------------------------------------
// app.post('/merge', (req, res) => {
//     const result = {};
//     // BAD: merging untrusted user input - prototype pollution risk
//     _.merge(result, req.body);
//     res.json(result);
// });

// // ------------------------------------------------------------
// // VULN 13: Insecure cookie (no Secure, no HttpOnly, no SameSite)
// // ZAP DAST will flag this
// // ------------------------------------------------------------
// app.get('/setcookie', (req, res) => {
//     res.setHeader('Set-Cookie', 'sessionId=abc123');  // missing Secure/HttpOnly/SameSite
//     res.send('Cookie set');
// });

// // ------------------------------------------------------------
// // VULN 14: Information disclosure via error messages
// // ZAP and SonarQube both flag verbose stack traces
// // ------------------------------------------------------------
// app.get('/debug', (req, res) => {
//     try {
//         throw new Error('Database connection failed: postgres://admin:' + DB_PASSWORD + '@db.internal:5432/prod');
//     } catch (e) {
//         // BAD: leaks full stack + secret in response
//         res.status(500).send('<pre>' + e.stack + '</pre>');
//     }
// });

// // ------------------------------------------------------------
// // VULN 15: CORS misconfiguration - allow any origin with credentials
// // ZAP DAST will flag this
// // ------------------------------------------------------------
// app.use((req, res, next) => {
//     res.setHeader('Access-Control-Allow-Origin', '*');
//     res.setHeader('Access-Control-Allow-Credentials', 'true');
//     next();
// });

// // ------------------------------------------------------------
// // Server bootstrap
// // ------------------------------------------------------------
// const PORT = process.env.PORT || 8080;
// app.listen(PORT, '0.0.0.0', () => {
//     console.log('M1 vulnerable test app listening on port ' + PORT);
//     console.log('DB password loaded: ' + DB_PASSWORD);  // BAD: secret in logs
// });



// {
//   "name": "m1-vulnerable-test-app",
//   "version": "1.0.0",
//   "main": "index.js",
//   "scripts": { "start": "node index.js" },
//   "dependencies": {
//     "express": "4.16.0",
//     "lodash": "4.17.4",
//     "minimist": "1.2.0",
//     "jsonwebtoken": "8.3.0",
//     "axios": "0.21.0",
//     "ejs": "3.1.6",
//     "ws": "7.4.5",
//     "node-fetch": "2.6.0",
//     "marked": "0.3.6",
//     "handlebars": "4.0.13",
//     "qs": "6.5.1",
//     "y18n": "4.0.0",
//     "ini": "1.3.5"
//   }
// }