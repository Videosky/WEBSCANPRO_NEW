const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = 3000;

// Create necessary directories
const dbDir = './db';
const publicDir = './public';

if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
    console.log('Created db directory');
}

if (!fs.existsSync(publicDir)) {
    fs.mkdirSync(publicDir, { recursive: true });
    console.log('Created public directory');
}

// Simple demo users (no bcrypt needed)
const users = [
    { 
        id: 1, 
        username: 'admin', 
        password: 'admin123', // Plain text for demo
        email: 'admin@webscanpro.com' 
    }
];

// Simple session storage
const sessions = {};

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(publicDir));

// Authentication middleware
const requireAuth = (req, res, next) => {
    const sessionId = req.headers['session-id'] || req.query.sessionId;
    if (sessionId && sessions[sessionId]) {
        req.userId = sessions[sessionId];
        next();
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
};

// WebSocket for real-time updates
const clients = new Set();

wss.on('connection', (ws) => {
    clients.add(ws);
    console.log('WebSocket client connected');

    ws.on('close', () => {
        clients.delete(ws);
        console.log('WebSocket client disconnected');
    });
});

function broadcastToClients(data) {
    const message = JSON.stringify(data);
    clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        }
    });
}

// Database setup
const db = new sqlite3.Database('./db/webscanpro.db', (err) => {
    if (err) {
        console.error('Database error:', err);
        return;
    }
    console.log('Connected to SQLite database');
    initializeDatabase();
});

function initializeDatabase() {
    db.serialize(() => {
        // Users table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Add default admin if not exists
        db.get('SELECT id FROM users WHERE username = ?', ['admin'], (err, row) => {
            if (!err && !row) {
                db.run(
                    'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                    ['admin', 'admin@webscanpro.com', 'admin123']
                );
                console.log('Default admin user created');
            }
        });

        // Scan history table
        db.run(`CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            target_url TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_time DATETIME,
            risk_score INTEGER DEFAULT 0,
            total_vulnerabilities INTEGER DEFAULT 0,
            critical INTEGER DEFAULT 0,
            high INTEGER DEFAULT 0,
            medium INTEGER DEFAULT 0,
            low INTEGER DEFAULT 0,
            response_time INTEGER,
            user_ip TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);

        // Vulnerabilities details
        db.run(`CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            title TEXT,
            severity TEXT,
            description TEXT,
            impact TEXT,
            recommendation TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )`);
        
        console.log('Database tables initialized');
    });
}

// Authentication Routes
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    // Check in-memory users first
    let user = users.find(u => u.username === username && u.password === password);
    
    // If not found, check database
    if (!user) {
        db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, dbUser) => {
            if (err || !dbUser) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Create session
            const sessionId = 'session_' + Date.now();
            sessions[sessionId] = dbUser.id;
            
            res.json({
                success: true,
                sessionId: sessionId,
                user: {
                    id: dbUser.id,
                    username: dbUser.username,
                    email: dbUser.email
                }
            });
        });
    } else {
        // Create session for in-memory user
        const sessionId = 'session_' + Date.now();
        sessions[sessionId] = user.id;
        
        res.json({
            success: true,
            sessionId: sessionId,
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });
    }
});

app.post('/api/auth/logout', (req, res) => {
    const sessionId = req.headers['session-id'];
    if (sessionId) {
        delete sessions[sessionId];
    }
    res.json({ success: true });
});

app.get('/api/auth/status', (req, res) => {
    const sessionId = req.headers['session-id'] || req.query.sessionId;
    if (sessionId && sessions[sessionId]) {
        const userId = sessions[sessionId];
        // Check in-memory users first
        let user = users.find(u => u.id === userId);
        
        if (!user) {
            // Check database
            db.get('SELECT * FROM users WHERE id = ?', [userId], (err, dbUser) => {
                if (err || !dbUser) {
                    return res.json({ authenticated: false });
                }
                res.json({
                    authenticated: true,
                    user: dbUser
                });
            });
        } else {
            res.json({
                authenticated: true,
                user: user
            });
        }
    } else {
        res.json({ authenticated: false });
    }
});

// User registration
app.post('/api/auth/register', (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    db.get('SELECT id FROM users WHERE username = ? OR email = ?', [username, email], (err, existingUser) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (existingUser) {
            return res.status(409).json({ error: 'Username or email already exists' });
        }
        
        db.run(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, password],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Failed to create user' });
                }
                
                res.json({
                    success: true,
                    message: 'Registration successful',
                    userId: this.lastID
                });
            }
        );
    });
});

// Routes for HTML pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/scanner', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'scanner.html'));
});

app.get('/reports', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'reports.html'));
});

app.get('/history', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'history.html'));
});

app.get('/analytics', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'analytics.html'));
});

// API Endpoints (protected)
app.post('/api/scan/start', requireAuth, (req, res) => {
    const { target_url, scan_type = 'full' } = req.body;
    const userId = req.userId;
    const user_ip = req.ip;
    const user_agent = req.get('User-Agent');

    db.run(
        `INSERT INTO scans (user_id, target_url, scan_type, status, start_time, user_ip, user_agent) 
         VALUES (?, ?, ?, 'running', CURRENT_TIMESTAMP, ?, ?)`,
        [userId, target_url, scan_type, user_ip, user_agent],
        function(err) {
            if (err) {
                console.error('Error starting scan:', err);
                return res.status(500).json({ error: 'Failed to start scan' });
            }

            const scanId = this.lastID;
            
            // Simulate scan completion after 3 seconds
            setTimeout(() => {
                completeScan(scanId, userId, target_url, scan_type);
            }, 3000);

            res.json({
                success: true,
                scan_id: scanId,
                message: 'Scan started successfully'
            });
        }
    );
});

function completeScan(scanId, userId, target_url, scan_type) {
    const risk_score = Math.floor(Math.random() * 100);
    const total_vulns = Math.floor(Math.random() * 20);
    const critical = Math.floor(Math.random() * Math.min(3, total_vulns));
    const high = Math.floor(Math.random() * Math.min(5, total_vulns - critical));
    const medium = Math.floor(Math.random() * Math.min(8, total_vulns - critical - high));
    const low = Math.max(0, total_vulns - critical - high - medium);
    const response_time = Math.floor(Math.random() * 5000) + 1000;

    db.run(
        `UPDATE scans SET 
            status = 'completed',
            end_time = CURRENT_TIMESTAMP,
            risk_score = ?,
            total_vulnerabilities = ?,
            critical = ?,
            high = ?,
            medium = ?,
            low = ?,
            response_time = ?
         WHERE id = ? AND user_id = ?`,
        [risk_score, total_vulns, critical, high, medium, low, response_time, scanId, userId],
        function(err) {
            if (!err && this.changes > 0) {
                addVulnerabilities(scanId, critical, high, medium, low);
                
                // Broadcast completion
                broadcastToClients({
                    type: 'scan_completed',
                    scanId: scanId,
                    target_url: target_url,
                    risk_score: risk_score,
                    total_vulnerabilities: total_vulns,
                    userId: userId
                });
            }
        }
    );
}

function addVulnerabilities(scanId, critical, high, medium, low) {
    const vulnerabilities = [];
    
    const vulnTypes = [
        { title: 'SQL Injection', severity: 'critical', description: 'Input fields susceptible to SQL injection', impact: 'Database compromise', recommendation: 'Use parameterized queries' },
        { title: 'Cross-Site Scripting (XSS)', severity: 'high', description: 'User input not sanitized', impact: 'Session hijacking', recommendation: 'Implement output encoding' },
        { title: 'Missing Security Headers', severity: 'medium', description: 'Security headers not configured', impact: 'Increased attack surface', recommendation: 'Add CSP, HSTS headers' },
        { title: 'Information Disclosure', severity: 'low', description: 'Server info exposed in headers', impact: 'Reconnaissance aid', recommendation: 'Hide server information' }
    ];

    // Add vulnerabilities
    for (let i = 0; i < critical; i++) {
        vulnerabilities.push({...vulnTypes[0], scan_id: scanId});
    }
    for (let i = 0; i < high; i++) {
        vulnerabilities.push({...vulnTypes[1], scan_id: scanId});
    }
    for (let i = 0; i < medium; i++) {
        vulnerabilities.push({...vulnTypes[2], scan_id: scanId});
    }
    for (let i = 0; i < low; i++) {
        vulnerabilities.push({...vulnTypes[3], scan_id: scanId});
    }

    // Insert into database
    if (vulnerabilities.length > 0) {
        const stmt = db.prepare(`INSERT INTO vulnerabilities 
            (scan_id, title, severity, description, impact, recommendation) 
            VALUES (?, ?, ?, ?, ?, ?)`);

        vulnerabilities.forEach(vuln => {
            stmt.run([scanId, vuln.title, vuln.severity, vuln.description, vuln.impact, vuln.recommendation]);
        });

        stmt.finalize();
    }
}

// Get scans
app.get('/api/scans', requireAuth, (req, res) => {
    const userId = req.userId;
    
    db.all('SELECT * FROM scans WHERE user_id = ? ORDER BY start_time DESC LIMIT 50', 
        [userId], 
        (err, scans) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch scans' });
            }
            res.json({ scans: scans || [] });
        }
    );
});

// Get reports
app.get('/api/reports', requireAuth, (req, res) => {
    const userId = req.userId;
    
    db.all(`SELECT * FROM scans WHERE user_id = ? AND status = 'completed' ORDER BY start_time DESC LIMIT 100`, 
        [userId], 
        (err, reports) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch reports' });
            }
            res.json(reports || []);
        }
    );
});

// Get scan details
app.get('/api/scan/:id', requireAuth, (req, res) => {
    const { id } = req.params;
    const userId = req.userId;

    db.get('SELECT * FROM scans WHERE id = ? AND user_id = ?', [id, userId], (err, scan) => {
        if (err || !scan) {
            return res.status(404).json({ error: 'Scan not found' });
        }

        db.all('SELECT * FROM vulnerabilities WHERE scan_id = ?', [id], (vulnErr, vulnerabilities) => {
            res.json({
                ...scan,
                vulnerabilities: vulnerabilities || []
            });
        });
    });
});

// Get stats
app.get('/api/stats', requireAuth, (req, res) => {
    const userId = req.userId;
    
    db.all(`
        SELECT 
            COUNT(*) as total_scans,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_scans,
            SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running_scans,
            AVG(risk_score) as avg_risk_score,
            SUM(total_vulnerabilities) as total_vulnerabilities,
            SUM(critical) as critical_vulns,
            SUM(high) as high_vulns,
            AVG(response_time) as avg_response_time
        FROM scans
        WHERE user_id = ?
    `, [userId], (err, rows) => {
        if (err) {
            return res.json({
                total_scans: 0,
                completed_scans: 0,
                running_scans: 0,
                avg_risk_score: 0,
                total_vulnerabilities: 0,
                critical_vulns: 0,
                high_vulns: 0,
                avg_response_time: 0
            });
        }
        res.json(rows[0] || {});
    });
});

// Delete scan
app.delete('/api/scan/:id', requireAuth, (req, res) => {
    const { id } = req.params;
    const userId = req.userId;

    db.run('DELETE FROM scans WHERE id = ? AND user_id = ?', [id, userId], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to delete scan' });
        }

        // Delete associated vulnerabilities
        db.run('DELETE FROM vulnerabilities WHERE scan_id = ?', [id]);

        broadcastToClients({
            type: 'scan_deleted',
            scanId: id,
            userId: userId
        });

        res.json({
            success: true,
            message: 'Scan deleted successfully'
        });
    });
});

// Start server
server.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
    console.log(`🔐 Login: http://localhost:${PORT}/login`);
    console.log(`📝 Register: http://localhost:${PORT}/register`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
    console.log(`🔍 Scanner: http://localhost:${PORT}/scanner`);
    console.log(`📋 Reports: http://localhost:${PORT}/reports`);
    console.log(`📜 History: http://localhost:${PORT}/history`);
    console.log(`📈 Analytics: http://localhost:${PORT}/analytics`);
    console.log(`\n🔐 Demo Credentials:`);
    console.log(`   Username: admin`);
    console.log(`   Password: admin123`);
    console.log(`\n📁 Project structure created successfully!`);
});