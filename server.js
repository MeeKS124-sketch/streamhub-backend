// server.js - Backend Server with Authentication & Admin Panel
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Database Setup
const db = new sqlite3.Database('./streamhub.db', (err) => {
    if (err) {
        console.error('Database error:', err);
    } else {
        console.log('✓ Database connected');
        initializeDatabase();
    }
});

// Initialize Database Tables
function initializeDatabase() {
    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            subscription_status TEXT DEFAULT 'free',
            subscription_expires DATE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Playlists table (admin-managed)
    db.run(`
        CREATE TABLE IF NOT EXISTS playlists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            group_name TEXT DEFAULT 'Uncategorized',
            description TEXT,
            subscription_required TEXT DEFAULT 'free',
            channel_count INTEGER DEFAULT 0,
            created_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    `);

    // User Favorites table
    db.run(`
        CREATE TABLE IF NOT EXISTS user_favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            folder_name TEXT NOT NULL,
            channels TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    // Create default admin user (password: admin123)
    db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, user) => {
        if (!user) {
            const adminPassword = bcrypt.hashSync('admin123', 10);
            db.run(`
                INSERT INTO users (username, email, password, role, subscription_status)
                VALUES ('admin', 'admin@streamhub.com', ?, 'admin', 'premium')
            `, [adminPassword], (err) => {
                if (!err) {
                    console.log('✓ Default admin created (username: admin, password: admin123)');
                } else {
                    console.error('Error creating admin:', err);
                }
            });
        } else {
            console.log('✓ Admin user already exists');
        }
    });
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token.' });
        }
        req.user = user;
        next();
    });
}

// Middleware to check admin role
function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required.' });
    }
    next();
}

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required.' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: 'Username or email already exists.' });
                    }
                    return res.status(500).json({ error: 'Registration failed.' });
                }

                const token = jwt.sign(
                    { id: this.lastID, username, role: 'user' },
                    JWT_SECRET,
                    { expiresIn: '7d' }
                );

                res.json({
                    message: 'Registration successful!',
                    token,
                    user: { id: this.lastID, username, role: 'user', subscription: 'free' }
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Server error.' });
    }
});

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required.' });
    }

    db.get(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        [username, username],
        async (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Server error.' });
            }

            if (!user) {
                return res.status(401).json({ error: 'Invalid credentials.' });
            }

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid credentials.' });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                JWT_SECRET,
                { expiresIn: '7d' }
            );

            res.json({
                message: 'Login successful!',
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    subscription: user.subscription_status,
                    subscriptionExpires: user.subscription_expires
                }
            });
        }
    );
});

// Get current user
app.get('/api/me', authenticateToken, (req, res) => {
    db.get('SELECT id, username, email, role, subscription_status, subscription_expires FROM users WHERE id = ?',
        [req.user.id],
        (err, user) => {
            if (err || !user) {
                return res.status(404).json({ error: 'User not found.' });
            }
            res.json(user);
        }
    );
});

// ==================== PLAYLIST ROUTES ====================

// Get all playlists (filtered by subscription)
app.get('/api/playlists', authenticateToken, (req, res) => {
    const userSubscription = req.user.subscription || 'free';
    
    db.all('SELECT * FROM playlists ORDER BY created_at DESC', [], (err, playlists) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch playlists.' });
        }

        // Filter playlists based on user subscription
        const filteredPlaylists = playlists.filter(p => {
            if (p.subscription_required === 'free') return true;
            if (userSubscription === 'premium') return true;
            return false;
        });

        res.json(filteredPlaylists);
    });
});

// Get single playlist content
app.get('/api/playlists/:id', authenticateToken, async (req, res) => {
    const playlistId = req.params.id;

    db.get('SELECT * FROM playlists WHERE id = ?', [playlistId], async (err, playlist) => {
        if (err || !playlist) {
            return res.status(404).json({ error: 'Playlist not found.' });
        }

        // Check subscription access
        if (playlist.subscription_required === 'premium' && req.user.subscription !== 'premium') {
            return res.status(403).json({ error: 'Premium subscription required.' });
        }

        try {
            // Fetch M3U content from URL
            const response = await fetch(playlist.url);
            const content = await response.text();

            res.json({
                ...playlist,
                content: content
            });
        } catch (error) {
            res.status(500).json({ error: 'Failed to fetch playlist content.' });
        }
    });
});

// ==================== ADMIN ROUTES ====================

// Add playlist (admin only)
app.post('/api/admin/playlists', authenticateToken, requireAdmin, (req, res) => {
    const { name, url, group_name, description, subscription_required, channel_count } = req.body;

    if (!name || !url) {
        return res.status(400).json({ error: 'Name and URL are required.' });
    }

    db.run(
        `INSERT INTO playlists (name, url, group_name, description, subscription_required, channel_count, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [name, url, group_name || 'Uncategorized', description, subscription_required || 'free', channel_count || 0, req.user.id],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to add playlist.' });
            }

            res.json({
                message: 'Playlist added successfully!',
                playlist: {
                    id: this.lastID,
                    name,
                    url,
                    group_name,
                    description,
                    subscription_required,
                    channel_count
                }
            });
        }
    );
});

// Update playlist (admin only)
app.put('/api/admin/playlists/:id', authenticateToken, requireAdmin, (req, res) => {
    const { name, url, group_name, description, subscription_required, channel_count } = req.body;
    const playlistId = req.params.id;

    db.run(
        `UPDATE playlists 
         SET name = ?, url = ?, group_name = ?, description = ?, subscription_required = ?, channel_count = ?
         WHERE id = ?`,
        [name, url, group_name, description, subscription_required, channel_count, playlistId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to update playlist.' });
            }

            if (this.changes === 0) {
                return res.status(404).json({ error: 'Playlist not found.' });
            }

            res.json({ message: 'Playlist updated successfully!' });
        }
    );
});

// Delete playlist (admin only)
app.delete('/api/admin/playlists/:id', authenticateToken, requireAdmin, (req, res) => {
    const playlistId = req.params.id;

    db.run('DELETE FROM playlists WHERE id = ?', [playlistId], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to delete playlist.' });
        }

        if (this.changes === 0) {
            return res.status(404).json({ error: 'Playlist not found.' });
        }

        res.json({ message: 'Playlist deleted successfully!' });
    });
});

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    db.all(
        'SELECT id, username, email, role, subscription_status, subscription_expires, created_at FROM users',
        [],
        (err, users) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch users.' });
            }
            res.json(users);
        }
    );
});

// Update user subscription (admin only)
app.put('/api/admin/users/:id/subscription', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;
    const { subscription_status, subscription_expires } = req.body;

    db.run(
        'UPDATE users SET subscription_status = ?, subscription_expires = ? WHERE id = ?',
        [subscription_status, subscription_expires, userId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to update subscription.' });
            }

            if (this.changes === 0) {
                return res.status(404).json({ error: 'User not found.' });
            }

            res.json({ message: 'Subscription updated successfully!' });
        }
    );
});

// ==================== FAVORITES ROUTES ====================

// Get user favorites
app.get('/api/favorites', authenticateToken, (req, res) => {
    db.all(
        'SELECT * FROM user_favorites WHERE user_id = ?',
        [req.user.id],
        (err, favorites) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch favorites.' });
            }

            const parsed = favorites.map(f => ({
                ...f,
                channels: JSON.parse(f.channels)
            }));

            res.json(parsed);
        }
    );
});

// Save favorites folder
app.post('/api/favorites', authenticateToken, (req, res) => {
    const { folder_name, channels } = req.body;

    db.run(
        'INSERT INTO user_favorites (user_id, folder_name, channels) VALUES (?, ?, ?)',
        [req.user.id, folder_name, JSON.stringify(channels)],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to save favorites.' });
            }

            res.json({ message: 'Favorites saved!', id: this.lastID });
        }
    );
});

// Start server
app.listen(PORT, () => {
    console.log(`\n🚀 StreamHub Server Running!`);
    console.log(`📍 http://localhost:${PORT}`);
    console.log(`\n👤 Default Admin Credentials:`);
    console.log(`   Username: admin`);
    console.log(`   Password: admin123\n`);
});

module.exports = app;
