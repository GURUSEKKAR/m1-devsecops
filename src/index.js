const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const ejs = require('ejs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

// VULNERABILITY: No security headers (ZAP will catch: missing CSP, X-Frame-Options, etc.)
// NOT using helmet on purpose

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// VULNERABILITY: Hardcoded secrets (SonarQube will catch)
const JWT_SECRET = 'super-secret-key-12345';
const DB_PASSWORD = 'admin123';
const API_KEY = 'sk-1234567890abcdef';

// In-memory "database" for demo
let users = [
  { id: 1, username: 'admin', password: 'admin123', role: 'admin' },
  { id: 2, username: 'user1', password: 'password', role: 'user' },
  { id: 3, username: 'guest', password: 'guest', role: 'guest' }
];

let messages = [
  { id: 1, user: 'admin', text: 'Welcome to M1 App!', timestamp: new Date().toISOString() }
];

// ==================== ROUTES ====================

// Home page
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>M1 DevSecOps Demo App</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #1B2A4A; }
        .vuln { background: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 10px 0; }
        a { color: #1e3799; }
        input, button { padding: 8px 12px; margin: 4px; }
        button { background: #1e3799; color: white; border: none; cursor: pointer; border-radius: 4px; }
        button:hover { background: #0c2461; }
        .messages { background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .msg { padding: 5px 0; border-bottom: 1px solid #ddd; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>M1 DevSecOps Demo Application</h1>
        <p>This application is <strong>intentionally vulnerable</strong> for security scanning demonstration.</p>
        
        <h3>Application Features:</h3>
        <ul>
          <li><a href="/login">Login Page</a> - Authentication</li>
          <li><a href="/search?q=test">Search</a> - Search functionality</li>
          <li><a href="/messages">Messages</a> - Message board</li>
          <li><a href="/profile/1">User Profile</a> - User information</li>
          <li><a href="/api/users">API: Users</a> - REST API</li>
          <li><a href="/health">Health Check</a> - System status</li>
          <li><a href="/debug">Debug Info</a> - System debug</li>
        </ul>

        <div class="vuln">
          <strong>Security Note:</strong> This app contains intentional vulnerabilities for 
          testing the M1 DevSecOps pipeline security scanners (Trivy, OWASP DC, SonarQube, ZAP).
        </div>
      </div>
    </body>
    </html>
  `);
});

// VULNERABILITY: XSS - User input directly reflected in HTML (SonarQube + ZAP will catch)
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  res.send(`
    <html>
    <head><title>Search Results</title></head>
    <body>
      <h2>Search Results for: ${query}</h2>
      <p>No results found for "${query}"</p>
      <form action="/search" method="GET">
        <input type="text" name="q" value="${query}" placeholder="Search...">
        <button type="submit">Search</button>
      </form>
      <a href="/">Back to Home</a>
    </body>
    </html>
  `);
});

// Login page
app.get('/login', (req, res) => {
  res.send(`
    <html>
    <head><title>Login</title></head>
    <body style="font-family:Arial;max-width:400px;margin:50px auto;">
      <h2>Login</h2>
      <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <button type="submit">Login</button>
      </form>
      <p><a href="/">Back to Home</a></p>
    </body>
    </html>
  `);
});

// VULNERABILITY: Plaintext password comparison, no rate limiting, no CSRF (SonarQube will catch)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(u => u.username === username && u.password === password);
  
  if (user) {
    // VULNERABILITY: Weak JWT config, no expiry
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET);
    
    // VULNERABILITY: Cookie without secure/httpOnly flags
    res.cookie('auth_token', token);
    res.cookie('user_role', user.role);
    
    res.send(`
      <html><body>
        <h2>Welcome ${user.username}!</h2>
        <p>Role: ${user.role}</p>
        <p>Token: ${token}</p>
        <a href="/">Go to Home</a>
      </body></html>
    `);
  } else {
    // VULNERABILITY: Information disclosure - tells if username exists
    const userExists = users.find(u => u.username === username);
    if (userExists) {
      res.status(401).send('Invalid password for user: ' + username);
    } else {
      res.status(401).send('User not found: ' + username);
    }
  }
});

// VULNERABILITY: IDOR - No authorization check, any user can view any profile
app.get('/profile/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const user = users.find(u => u.id === userId);
  
  if (user) {
    // VULNERABILITY: Exposing sensitive data (password)
    res.json({
      id: user.id,
      username: user.username,
      password: user.password,
      role: user.role
    });
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// Messages page
app.get('/messages', (req, res) => {
  let messageHtml = messages.map(m => 
    `<div class="msg"><strong>${m.user}</strong>: ${m.text} <small>(${m.timestamp})</small></div>`
  ).join('');
  
  res.send(`
    <html>
    <head><title>Messages</title></head>
    <body style="font-family:Arial;max-width:600px;margin:50px auto;">
      <h2>Message Board</h2>
      <div style="background:#f0f0f0;padding:15px;border-radius:5px;">
        ${messageHtml}
      </div>
      <br>
      <form action="/messages" method="POST">
        <input type="text" name="user" placeholder="Your name" required>
        <input type="text" name="text" placeholder="Your message" required style="width:300px;">
        <button type="submit">Post</button>
      </form>
      <p><a href="/">Back to Home</a></p>
    </body>
    </html>
  `);
});

// VULNERABILITY: Stored XSS - Message text not sanitized
app.post('/messages', (req, res) => {
  const { user, text } = req.body;
  messages.push({
    id: messages.length + 1,
    user: user,
    text: text,
    timestamp: new Date().toISOString()
  });
  res.redirect('/messages');
});

// VULNERABILITY: SQL injection pattern (SonarQube will catch even without real DB)
app.get('/api/search-users', (req, res) => {
  const searchTerm = req.query.name;
  // VULNERABILITY: String concatenation in query (SQL Injection)
  const query = "SELECT * FROM users WHERE username = '" + searchTerm + "'";
  console.log('Executing query: ' + query);
  
  // Simulated result
  const result = users.filter(u => u.username.includes(searchTerm || ''));
  res.json(result);
});

// API: Get all users
app.get('/api/users', (req, res) => {
  // VULNERABILITY: Exposing all user data including passwords
  res.json(users);
});

// VULNERABILITY: Command injection pattern (SonarQube will catch)
app.get('/api/ping', (req, res) => {
  const host = req.query.host || 'localhost';
  const exec = require('child_process').exec;
  // VULNERABILITY: Command injection - user input passed directly to exec
  exec('ping -c 1 ' + host, (error, stdout, stderr) => {
    res.json({ output: stdout || stderr || 'No response' });
  });
});

// VULNERABILITY: Path traversal (SonarQube will catch)
app.get('/api/file', (req, res) => {
  const filename = req.query.name;
  // VULNERABILITY: No path sanitization - directory traversal possible
  const filepath = path.join(__dirname, 'uploads', filename);
  res.sendFile(filepath);
});

// VULNERABILITY: Debug endpoint exposing system info (ZAP will catch)
app.get('/debug', (req, res) => {
  res.json({
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    memory: process.memoryUsage(),
    uptime: process.uptime(),
    env: {
      NODE_ENV: process.env.NODE_ENV,
      PORT: process.env.PORT,
      // VULNERABILITY: Exposing environment variables
      PATH: process.env.PATH
    },
    cwd: process.cwd(),
    pid: process.pid
  });
});

// VULNERABILITY: Open redirect (ZAP will catch)
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  // VULNERABILITY: No validation of redirect URL
  res.redirect(url);
});

// VULNERABILITY: Insecure eval usage (SonarQube will catch)
app.post('/api/calculate', (req, res) => {
  const { expression } = req.body;
  try {
    // VULNERABILITY: eval() with user input - Remote Code Execution
    const result = eval(expression);
    res.json({ result: result });
  } catch (e) {
    res.status(400).json({ error: 'Invalid expression' });
  }
});

// VULNERABILITY: Insecure randomness for tokens (SonarQube will catch)
app.get('/api/token', (req, res) => {
  // VULNERABILITY: Math.random() is not cryptographically secure
  const token = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
  res.json({ token: token });
});

// VULNERABILITY: No rate limiting on sensitive endpoint
app.post('/api/reset-password', (req, res) => {
  const { username, newPassword } = req.body;
  const user = users.find(u => u.username === username);
  if (user) {
    user.password = newPassword;
    res.json({ message: 'Password reset successful for ' + username });
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// VULNERABILITY: Verbose error handling exposing stack traces
app.use((err, req, res, next) => {
  // VULNERABILITY: Stack trace exposed to client
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    path: req.path
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`M1 DevSecOps Demo App running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`DB Password: ${DB_PASSWORD}`);
  console.log(`API Key: ${API_KEY}`);
});
