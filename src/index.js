const http = require('http');
const url = require('url');
const exec = require('child_process').exec;
const fs = require('fs');

const PORT = 8080;

// VULNERABILITY 1: Hardcoded credentials (CWE-798)
const DB_PASSWORD = "admin123";
const SECRET_KEY  = "mysecretkey_hardcoded";
const API_TOKEN   = "tok_live_abc123supersecret";

http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname  = parsedUrl.pathname;
  const query     = parsedUrl.query;

  // VULNERABILITY 2: Command Injection (CWE-78)
  // User input is passed directly to exec() without sanitization
  if (pathname === '/ping') {
    const host = query.host;
    exec(`ping -c 1 ${host}`, (err, stdout) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(stdout || err.message);
    });
    return;
  }

  // VULNERABILITY 3: Path Traversal (CWE-22)
  // Attacker can request /read?file=../../etc/passwd
  if (pathname === '/read') {
    const filePath = query.file;
    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error: ' + err.message);  // VULNERABILITY 4: Verbose error disclosure (CWE-209)
      } else {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(data);
      }
    });
    return;
  }

  // VULNERABILITY 5: Reflected XSS (CWE-79)
  // User input is reflected back in HTML without encoding
  if (pathname === '/hello') {
    const name = query.name || 'World';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<h1>Hello, ${name}!</h1>`);  // No sanitization!
    return;
  }

  // VULNERABILITY 6: Sensitive data exposure (CWE-200)
  // Debug endpoint leaks credentials and config
  if (pathname === '/debug') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      db_password: DB_PASSWORD,
      api_token:   API_TOKEN,
      secret_key:  SECRET_KEY,
      env:         process.env        // Exposes ALL environment variables!
    }));
    return;
  }

  // VULNERABILITY 7: No authentication or authorization on any route (CWE-306)
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<h1>M1 DevSecOps Vulnerable App</h1><p>Training purposes only.</p>');

}).listen(PORT, () => {
  console.log(`Vulnerable server running on port ${PORT}`);
});