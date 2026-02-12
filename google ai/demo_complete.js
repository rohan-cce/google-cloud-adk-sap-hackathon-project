const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const app = express();

// ==========================================
// 1. HARDCODED CREDENTIALS (CWE-798)
// ==========================================

const aws_config = {
    // 🔴 Critical
    accessKeyId: "AKIA1234567890EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
};

const DB_PASSWORD = "supersecretpassword123";  // 🔴 Critical

// ==========================================
// 2. CROSS-SITE SCRIPTING (XSS) (CWE-79)
// ==========================================

function updateProfile(userInput) {
    const profileDiv = document.getElementById('profile');

    // 🟠 High: innerHTML allows script execution
    profileDiv.innerHTML = "Welcome, " + userInput;

    // 🟠 High: document.write is dangerous
    document.write("<div>" + userInput + "</div>");

    // 🟠 High: jQuery .html() is also unsafe
    $('#message').html(userInput);
}

// ==========================================
// 3. CODE INJECTION (CWE-94)
// ==========================================

function calculate(input) {
    // 🔴 Critical: eval() can run arbitrary code
    return eval(input);
}

// ==========================================
// 4. WEAK CRYPTOGRAPHY (CWE-327)
// ==========================================

function hashPassword(password) {
    // 🟡 Medium: MD5 is broken
    return crypto.createHash('md5').update(password).digest('hex');
}

function legacyHash(data) {
    // 🟡 Medium: SHA1 is deprecated
    return crypto.createHash('sha1').update(data).digest('hex');
}

// ==========================================
// 5. PATH TRAVERSAL (CWE-22)
// ==========================================

app.get('/download', (req, res) => {
    // 🟠 High: User can request "../../etc/passwd"
    // Direct usage of req.query triggers the detector
    const data = fs.readFileSync(req.query.file, 'utf8');
    res.send(data);
});
