// Vulnerable JavaScript code — for testing the Security Review Agent
// This file contains INTENTIONAL security vulnerabilities. DO NOT use in production.

const fs = require('fs');
const http = require('http');
const crypto = require('crypto');

// ❌ CWE-798: Hardcoded API key
const API_KEY = "AIzaSyC1234567890abcdefghijklmnop";
const DATABASE_PASSWORD = "admin123!@#";
const JWT_SECRET = "my-super-secret-jwt-key-never-change";

// ❌ CWE-79: Cross-Site Scripting via innerHTML
function displayUserComment(comment) {
    const container = document.getElementById('comments');
    // XSS: Directly injecting user content into DOM
    container.innerHTML = '<div class="comment">' + comment + '</div>';
}

// ❌ CWE-79: XSS via document.write
function renderWelcomeMessage(username) {
    document.write('<h1>Welcome, ' + username + '!</h1>');
}

// ❌ CWE-22: Path traversal
function getUserAvatar(req, res) {
    const filename = req.query.filename;
    // No path sanitization — attacker can use ../../etc/passwd
    const filepath = './uploads/' + filename;
    const data = fs.readFileSync(filepath);
    res.send(data);
}

// ❌ CWE-89: SQL-like injection (NoSQL in this case)
function findUser(username) {
    const query = "SELECT * FROM users WHERE username = '" + username + "'";
    // String concatenation in query
    return db.execute(query);
}

// ❌ CWE-94: Code injection via eval
function calculateExpression(userInput) {
    // eval() on user input — remote code execution
    return eval(userInput);
}

// ❌ CWE-327: Weak hashing
function hashToken(token) {
    return crypto.createHash('md5').update(token).digest('hex');
}

// ❌ CWE-327: SHA1 is also weak for security-sensitive operations
function hashPassword(password) {
    return crypto.createHash('sha1').update(password).digest('hex');
}

// Create a simple HTTP server (for context)
const server = http.createServer((req, res) => {
    if (req.url.startsWith('/avatar')) {
        getUserAvatar(req, res);
    } else if (req.url.startsWith('/calculate')) {
        const expr = new URL(req.url, 'http://localhost').searchParams.get('expr');
        const result = calculateExpression(expr);
        res.end(JSON.stringify({ result }));
    } else {
        res.end('Security Review Agent Test Server');
    }
});

server.listen(3000, () => {
    console.log('Server running on port 3000');
    console.log('API Key:', API_KEY); // ❌ Logging sensitive data
});
