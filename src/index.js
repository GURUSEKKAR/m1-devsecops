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