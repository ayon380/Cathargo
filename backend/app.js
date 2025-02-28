const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const natural = require('natural');
const multer = require('multer');
const fs = require('fs');
const cors = require('cors');
const path = require('path');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const cron = require('node-cron');

const app = express();
const JWT_SECRET = 'your-secret-key'; // In production, use environment variable
const upload = multer({ dest: 'uploads/' });

app.use(express.json());
app.use(cors());
// Initialize SQLite database
const db = new sqlite3.Database('scanner.db');

// Initialize database tables
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    credits INTEGER DEFAULT 20,
    last_reset DATE DEFAULT CURRENT_DATE
  )`);

    // Documents table
    db.run(`CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    filename TEXT,
    content TEXT,
    upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

    // Credit requests table
    db.run(`CREATE TABLE IF NOT EXISTS credit_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    amount INTEGER,
    status TEXT DEFAULT 'pending',
    request_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

    // Activity logs table
    db.run(`CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    activity TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});
const initializeAdminUser = async () => {
    const username = 'admin';
    const password = 'admin';
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
        `INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, 'admin')`,
        [username, hashedPassword],
        (err) => {
            if (err) {
                console.error('Error creating admin user:', err.message);
            } else {
                console.log('Admin user initialized');
            }
        }
    );
};
initializeAdminUser();
// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access denied' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Middleware to check if user is admin
const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Check and reset daily credits
const checkAndResetCredits = async (userId) => {
    return new Promise((resolve, reject) => {
        db.get(
            'SELECT credits, last_reset FROM users WHERE id = ?',
            [userId],
            (err, row) => {
                if (err) {
                    reject(err);
                    return;
                }

                const lastReset = new Date(row.last_reset);
                const today = new Date();

                if (lastReset.toDateString() !== today.toDateString()) {
                    db.run(
                        'UPDATE users SET credits = 20, last_reset = CURRENT_DATE WHERE id = ?',
                        [userId],
                        (err) => {
                            if (err) {
                                reject(err);
                                return;
                            }
                            resolve(20);
                        }
                    );
                } else {
                    resolve(row.credits);
                }
            }
        );
    });
};

// Function to reset credits
const resetCredits = () => {
    db.run('UPDATE users SET credits = 20, last_reset = CURRENT_DATE', (err) => {
        if (err) {
            console.error('Error resetting credits:', err.message);
        } else {
            console.log('Credits reset successfully');
        }
    });
};

// Schedule job to reset credits at midnight IST
cron.schedule('0 0 * * *', () => {
    // Convert IST to UTC (IST is UTC+5:30)
    const now = new Date();
    const utcHour = now.getUTCHours();
    const utcMinute = now.getUTCMinutes();
    if (utcHour === 18 && utcMinute === 30) {
        resetCredits();
    }
}, {
    timezone: "Asia/Kolkata"
});

// Register endpoint
app.post('/auth/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword],
            function (err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: 'Username already exists' });
                    }
                    return res.status(500).json({ error: 'Database error' });
                }

                const token = jwt.sign(
                    { id: this.lastID, username, role: 'user' },
                    JWT_SECRET
                );
                res.json({ token });
            }
        );
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});


// ... (previous code remains the same until the admin endpoints)

// Get all pending credit requests
app.get('/admin/credits/requests', authenticateToken, isAdmin, (req, res) => {
    db.all(
        `SELECT cr.*, u.username 
       FROM credit_requests cr 
       JOIN users u ON cr.user_id = u.id 
       WHERE cr.status = 'pending'
       ORDER BY cr.request_date DESC`,
        (err, requests) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ requests });
        }
    );
});

// Deny credit request endpoint
app.post('/admin/credits/deny/:requestId', authenticateToken, isAdmin, (req, res) => {
    const { requestId } = req.params;

    db.run(
        'UPDATE credit_requests SET status = "denied" WHERE id = ?',
        [requestId],
        (err) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ message: 'Credit request denied successfully' });
        }
    );
});

// Get user's scan history
app.get('/user/scan-history', authenticateToken, (req, res) => {
    db.all(
        `SELECT 
        d.id,
        d.filename,
        d.upload_date,
        (SELECT COUNT(*) FROM documents WHERE user_id = ? AND upload_date <= d.upload_date) as scan_number
       FROM documents d
       WHERE d.user_id = ?
       ORDER BY d.upload_date DESC`,
        [req.user.id, req.user.id],
        (err, scans) => {
            if (err) return res.status(500).json({ error: 'Database error' });

            // Format dates and add additional info
            const formattedScans = scans.map(scan => ({
                ...scan,
                upload_date: new Date(scan.upload_date).toISOString(),
                formatted_date: new Date(scan.upload_date).toLocaleString()
            }));

            res.json({ scans: formattedScans });
        }
    );
});

// Endpoint to download scan history as a text file
app.get('/user/scan-history/download', authenticateToken, (req, res) => {
    db.all(
        `SELECT 
        d.filename,
        d.upload_date,
        (SELECT COUNT(*) FROM documents WHERE user_id = ? AND upload_date <= d.upload_date) as scan_number
       FROM documents d
       WHERE d.user_id = ?
       ORDER BY d.upload_date DESC`,
        [req.user.id, req.user.id],
        (err, scans) => {
            if (err) return res.status(500).json({ error: 'Database error' });

            // Format scan history as text
            let scanHistory = 'Scan History:\n\n';
            scans.forEach(scan => {
                scanHistory += `Scan Number: ${scan.scan_number}\n`;
                scanHistory += `Filename: ${scan.filename}\n`;
                scanHistory += `Upload Date: ${new Date(scan.upload_date).toLocaleString()}\n\n`;
            });

            // Set response headers for file download
            res.setHeader('Content-Disposition', 'attachment; filename="scan_history.txt"');
            res.setHeader('Content-Type', 'text/plain');
            res.send(scanHistory);
        }
    );
});

// Get specific scan details
app.get('/user/scan/:scanId', authenticateToken, (req, res) => {
    const { scanId } = req.params;

    db.get(
        'SELECT * FROM documents WHERE id = ? AND user_id = ?',
        [scanId, req.user.id],
        (err, scan) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (!scan) return res.status(404).json({ error: 'Scan not found' });

            // Find similar documents for this scan
            const tfidf = new natural.TfIdf();

            // Add the current document
            tfidf.addDocument(scan.content);

            // Get all other documents by this user
            db.all(
                'SELECT * FROM documents WHERE user_id = ? AND id != ?',
                [req.user.id, scanId],
                (err, documents) => {
                    if (err) return res.status(500).json({ error: 'Database error' });

                    // Calculate similarities
                    const similarities = documents.map((doc, idx) => {
                        tfidf.addDocument(doc.content);
                        // Calculate similarity (0-100%)
                        const similarityScore = computeCosineSimilarity(tfidf, 0, idx + 1) * 100;
                       
                        let similarity = 0
                        if (similarityScore == 100) {
                            similarity = 100
                        }
                        else {
                            similarity = (similarityScore * 10).toFixed(2)
                        }
                        console.log('Similarity:', similarity);
                        return {
                                id: doc.id,
                                filename: doc.filename,
                                upload_date: doc.upload_date,
                                similarity:similarity// Ensure max is 100%
                            };
                    });

                    // Sort by similarity
                    similarities.sort((a, b) => b.similarity - a.similarity);

                    res.json({
                        scan: {
                            ...scan,
                            upload_date: new Date(scan.upload_date).toISOString(),
                            formatted_date: new Date(scan.upload_date).toLocaleString()
                        },
                        similar_documents: similarities.slice(0, 5)
                    });
                }
            );
        }
    );
});

// Helper function to compute cosine similarity
function computeCosineSimilarity(tfidf, indexA, indexB) {
    const termsA = tfidf.listTerms(indexA);
    const termsB = tfidf.listTerms(indexB);

    let dot = 0;
    let magA = 0;
    let magB = 0;
    const termsBMap = {};

    // Build a map for doc B term weights
    termsB.forEach(t => { termsBMap[t.term] = t.tfidf; });

    // Dot product and magnitude of doc A
    termsA.forEach(tA => {
        const weightB = termsBMap[tA.term] || 0;
        dot += tA.tfidf * weightB;
        magA += tA.tfidf * tA.tfidf;
    });

    // Magnitude of doc B
    termsB.forEach(tB => {
        magB += tB.tfidf * tB.tfidf;
    });

    const denom = Math.sqrt(magA) * Math.sqrt(magB);
    // Return a value between 0 and 1
    return denom ? Math.min(1, Math.max(0, dot / denom)) : 0;
}

// ... (rest of the previous code remains the same)
// Login endpoint
app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;

    db.get(
        'SELECT * FROM users WHERE username = ?',
        [username],
        async (err, user) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (!user) return res.status(400).json({ error: 'User not found' });

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(400).json({ error: 'Invalid password' });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                JWT_SECRET
            );
            res.json({ token });
        }
    );
});

// Get user profile endpoint
app.get('/user/profile', authenticateToken, async (req, res) => {
    const credits = await checkAndResetCredits(req.user.id);

    db.get(
        'SELECT id, username, role, credits, last_reset FROM users WHERE id = ?',
        [req.user.id],
        (err, user) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (!user) return res.status(404).json({ error: 'User not found' });
            res.json(user);
        }
    );
});

// Document scan endpoint
app.post('/scan', authenticateToken, upload.single('document'), async (req, res) => {
    try {
        const credits = await checkAndResetCredits(req.user.id);

        if (credits <= 0) {
            return res.status(403).json({ error: 'No credits available' });
        }

        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Read uploaded file content
        let content = '';
        const filePath = req.file.path;
        const fileExt = path.extname(req.file.originalname).toLowerCase();

        if (fileExt === '.pdf') {
            const dataBuffer = fs.readFileSync(filePath);
            const pdfData = await pdfParse(dataBuffer);
            content = pdfData.text;
        } else if (fileExt === '.docx') {
            const result = await mammoth.extractRawText({ path: filePath });
            content = result.value;
        } else {
            content = fs.readFileSync(filePath, 'utf8');
        }

        // Save the file to the uploads directory
        const uploadPath = path.join(__dirname, 'uploads', req.file.originalname);
        fs.renameSync(filePath, uploadPath);

        // Store document in database
        db.run(
            'INSERT INTO documents (user_id, filename, content) VALUES (?, ?, ?)',
            [req.user.id, req.file.originalname, content],
            async function (err) {
                if (err) {
                    return res.status(500).json({ error: 'Database error' });
                }

                // Deduct credit
                await new Promise((resolve, reject) => {
                    db.run(
                        'UPDATE users SET credits = credits - 1 WHERE id = ?',
                        [req.user.id],
                        (err) => {
                            if (err) reject(err);
                            else resolve();
                        }
                    );
                });

                // Log activity
                db.run(
                    'INSERT INTO activity_logs (user_id, activity) VALUES (?, ?)',
                    [req.user.id, 'Scanned a document'],
                    (err) => {
                        if (err) console.error('Error logging activity:', err.message);
                    }
                );

                // Find similar documents using NLP
                db.all(
                    'SELECT * FROM documents WHERE user_id = ?',
                    [req.user.id],
                    (err, documents) => {
                        if (err) {
                            return res.status(500).json({ error: 'Database error' });
                        }

                        // Use natural's TfIdf for document similarity
                        const tfidf = new natural.TfIdf();

                        // Add the new document
                        tfidf.addDocument(content);

                        // Add existing documents and calculate similarity
                        const similarities = documents.map((doc, idx) => {
                            tfidf.addDocument(doc.content);

                            // Calculate similarity score (0-100%)
                            const similarityScore = computeCosineSimilarity(tfidf, 0, idx + 1) * 100;
                            console.log('Similarity:', similarityScore);

                            return {
                                id: doc.id,
                                filename: doc.filename,
                                similarity: Math.min(100, similarityScore).toFixed(2) // Ensure max is 100%
                            };
                        });

                        // Sort by similarity score
                        similarities.sort((a, b) => b.similarity - a.similarity);

                        res.json({
                            message: 'Document scanned successfully',
                            documentId: this.lastID,
                            similarDocuments: similarities.slice(0, 5) // Return top 5 similar docs
                        });
                    }
                );
            }
        );
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Request more credits endpoint
app.post('/credits/request', authenticateToken, (req, res) => {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
        return res.status(400).json({ error: 'Invalid credit amount' });
    }

    db.run(
        'INSERT INTO credit_requests (user_id, amount) VALUES (?, ?)',
        [req.user.id, amount],
        function (err) {
            if (err) return res.status(500).json({ error: 'Database error' });

            // Log activity
            db.run(
                'INSERT INTO activity_logs (user_id, activity) VALUES (?, ?)',
                [req.user.id, `Requested ${amount} credits`],
                (err) => {
                    if (err) console.error('Error logging activity:', err.message);
                }
            );

            res.json({
                message: 'Credit request submitted successfully',
                requestId: this.lastID
            });
        }
    );
});

// Admin endpoints
app.get('/admin/analytics', authenticateToken, isAdmin, (req, res) => {
    const analytics = {};

    // Get total users
    db.get('SELECT COUNT(*) as total FROM users', (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        analytics.totalUsers = result.total;

        // Get total documents
        db.get('SELECT COUNT(*) as total FROM documents', (err, result) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            analytics.totalDocuments = result.total;

            // Get pending credit requests
            db.get(
                'SELECT COUNT(*) as total FROM credit_requests WHERE status = "pending"',
                (err, result) => {
                    if (err) return res.status(500).json({ error: 'Database error' });
                    analytics.pendingRequests = result.total;

                    res.json(analytics);
                }
            );
        });
    });
});

// Admin approve credit request endpoint
app.post('/admin/credits/approve/:requestId', authenticateToken, isAdmin, (req, res) => {
    const { requestId } = req.params;

    db.get(
        'SELECT * FROM credit_requests WHERE id = ?',
        [requestId],
        (err, request) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (!request) return res.status(404).json({ error: 'Request not found' });

            db.run('BEGIN TRANSACTION', (err) => {
                if (err) return res.status(500).json({ error: 'Database error' });

                db.run(
                    'UPDATE credit_requests SET status = "approved" WHERE id = ?',
                    [requestId],
                    (err) => {
                        if (err) {
                            db.run('ROLLBACK');
                            return res.status(500).json({ error: 'Database error' });
                        }

                        db.run(
                            'UPDATE users SET credits = credits + ? WHERE id = ?',
                            [request.amount, request.user_id],
                            (err) => {
                                if (err) {
                                    db.run('ROLLBACK');
                                    return res.status(500).json({ error: 'Database error' });
                                }

                                db.run('COMMIT', (err) => {
                                    if (err) return res.status(500).json({ error: 'Database error' });
                                    res.json({ message: 'Credit request approved successfully' });
                                });
                            }
                        );
                    }
                );
            });
        }
    );
});

// Track the number of scans per user per day
app.get('/admin/analytics/scans-per-user', authenticateToken, isAdmin, (req, res) => {
    db.all(
        `SELECT user_id, COUNT(*) as scan_count, DATE(upload_date) as scan_date
         FROM documents
         GROUP BY user_id, scan_date
         ORDER BY scan_date DESC`,
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ scansPerUser: rows });
        }
    );
});

// Identify most common scanned document topics
app.get('/admin/analytics/common-topics', authenticateToken, isAdmin, (req, res) => {
    db.all(
        `SELECT content FROM documents`,
        (err, documents) => {
            if (err) return res.status(500).json({ error: 'Database error' });

            const tfidf = new natural.TfIdf();
            documents.forEach(doc => tfidf.addDocument(doc.content));

            const topics = [];
            tfidf.documents.forEach((doc, index) => {
                tfidf.listTerms(index).slice(0, 5).forEach(term => {
                    topics.push(term.term);
                });
            });

            const topicCounts = topics.reduce((acc, topic) => {
                acc[topic] = (acc[topic] || 0) + 1;
                return acc;
            }, {});

            res.json({ commonTopics: topicCounts });
        }
    );
});

// View top users by scans and credit usage
app.get('/admin/analytics/top-users', authenticateToken, isAdmin, (req, res) => {
    db.all(
        `SELECT u.username, COUNT(d.id) as scan_count, u.credits
         FROM users u
         LEFT JOIN documents d ON u.id = d.user_id
         WHERE u.role != 'admin'
         GROUP BY u.id
         ORDER BY scan_count DESC, u.credits DESC
         LIMIT 10`,
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ topUsers: rows });
        }
    );
});

// Generate credit usage statistics for admins
app.get('/admin/analytics/credit-usage', authenticateToken, isAdmin, (req, res) => {
    db.all(
        `SELECT u.username, u.credits, COUNT(cr.id) as credit_requests
         FROM users u
         LEFT JOIN credit_requests cr ON u.id = cr.user_id
         WHERE u.role != 'admin'
         GROUP BY u.id
         ORDER BY credit_requests DESC, u.credits DESC`,
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ creditUsage: rows });
        }
    );
});

// Adjust user credit balance (Admin only)
app.post('/admin/credits/adjust', authenticateToken, isAdmin, (req, res) => {
    const { username, amount, reason } = req.body;

    if (!username || !amount || !reason) {
        return res.status(400).json({ error: 'Username, amount, and reason are required' });
    }

    db.get('SELECT id, credits FROM users WHERE username = ?', [username], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.status(404).json({ error: 'User not found' });

        const newBalance = user.credits + parseInt(amount);
        if (newBalance < 0) {
            return res.status(400).json({ error: 'Credit balance cannot be negative' });
        }

        db.run(
            'UPDATE users SET credits = ? WHERE id = ?',
            [newBalance, user.id],
            (err) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                res.json({
                    message: 'Credit balance adjusted successfully',
                    newBalance: newBalance
                });
            }
        );
    });
});

// Admin endpoint to get user activity logs
app.get('/admin/activity-logs', authenticateToken, isAdmin, (req, res) => {
    db.all(
        `SELECT al.*, u.username 
         FROM activity_logs al 
         JOIN users u ON al.user_id = u.id 
         ORDER BY al.timestamp DESC`,
        (err, logs) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ logs });
        }
    );
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});