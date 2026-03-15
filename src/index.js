const http = require('http');
const PORT = 8080;

http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<h1>M1 DevSecOps App</h1><p>Pipeline running successfully.</p>');
}).listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
