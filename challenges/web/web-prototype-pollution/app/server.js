const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const ejs = require('ejs');
const fs = require('fs');
const { execSync } = require('child_process');

const app = express();
const FLAG = process.env.FLAG || 'HL4{EJEMPLO_LOCAL}';

// Write flag to file
fs.writeFileSync('/flag.txt', FLAG);

app.set('view engine', 'ejs');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'session-secret-xyz', resave: false, saveUninitialized: true }));

// Vulnerable deep merge function
function deepMerge(target, source) {
    for (let key in source) {  // vulnerable: no hasOwnProperty check
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Application config
let appConfig = {
    theme: 'default',
    language: 'en',
    debug: false
};

// Routes
app.get('/', (req, res) => res.render('index', { config: appConfig }));

app.get('/login', (req, res) => res.render('login'));
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === 'admin123') {
        req.session.user = { username: 'admin', role: 'admin' };
    } else if (username === 'user1' && password === 'user1pass') {
        req.session.user = { username: 'user1', role: 'user' };
    } else {
        return res.render('login', { error: 'Invalid credentials' });
    }
    res.redirect('/dashboard');
});

app.get('/dashboard', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.render('dashboard', { user: req.session.user, config: appConfig });
});

// VULNERABLE endpoint - deep merge without hasOwnProperty
app.post('/api/config', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    const userConfig = req.body;
    deepMerge(appConfig, userConfig);
    res.json({ success: true, config: appConfig });
});

// Report renderer using EJS
app.get('/report', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const template = req.query.template || 'default';
    const templateFile = `/app/views/reports/${template}.ejs`;
    try {
        // EJS render - uses appConfig settings (polluted __proto__ affects behavior)
        const html = ejs.render(fs.readFileSync(templateFile, 'utf8'), {
            user: req.session.user,
            config: appConfig,
            title: 'Report'
        });
        res.send(html);
    } catch (e) {
        res.status(500).send('Template error: ' + e.message);
    }
});

app.listen(8080, () => console.log('Server running on 8080'));
