// server.js - Backend Server with Authentication & Admin Panel
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const https = require('https');
const http = require('http');

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

    // Payments/Subscriptions table
    db.run(`
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount DECIMAL(10,2) NOT NULL,
            plan TEXT NOT NULL,
            payment_method TEXT,
            payment_status TEXT DEFAULT 'completed',
            transaction_id TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `, (err) => {
        if (!err) {
            console.log('✓ Payments table ready');
        }
    });

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
                { id: user.id, username: user.username, role: user.role, subscription: user.subscription_status },
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
    db.get('SELECT id, username, email, role, subscription_status, subscription_expires, created_at FROM users WHERE id = ?',
        [req.user.id],
        (err, user) => {
            if (err || !user) {
                return res.status(404).json({ error: 'User not found.' });
            }
            res.json(user);
        }
    );
});

// Change password
app.put('/api/me/password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Current and new password required.' });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'New password must be at least 6 characters.' });
    }

    db.get('SELECT * FROM users WHERE id = ?', [req.user.id], async (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: 'User not found.' });
        }

        // Verify current password
        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Current password is incorrect.' });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update password
        db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.user.id], (err) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to update password.' });
            }

            res.json({ message: 'Password updated successfully!' });
        });
    });
});

// ==================== PLAYLIST ROUTES ====================

// Get all playlists (filtered by subscription)
app.get('/api/playlists', authenticateToken, (req, res) => {
    console.log(`📋 User ${req.user.username} requesting playlists (subscription: ${req.user.subscription || 'free'})`);
    
    db.all('SELECT * FROM playlists ORDER BY created_at DESC', [], (err, playlists) => {
        if (err) {
            console.error('❌ Error fetching playlists:', err);
            return res.status(500).json({ error: 'Failed to fetch playlists.' });
        }

        console.log(`📊 Found ${playlists.length} total playlists in database`);

        // Filter playlists based on user subscription (3-tier system)
        const userSubscription = req.user.subscription || 'free';
        const filteredPlaylists = playlists.filter(p => {
            const required = p.subscription_required || 'free';
            
            // Free plan: Only free content
            if (userSubscription === 'free') {
                return required === 'free';
            }
            
            // Lite plan: Free + Lite content
            if (userSubscription === 'lite') {
                return required === 'free' || required === 'lite';
            }
            
            // Premium plan: Everything
            if (userSubscription === 'premium') {
                return true;
            }
            
            return false;
        });

        console.log(`✅ Returning ${filteredPlaylists.length} playlists to user`);
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

        // Check subscription access (3-tier system)
        const required = playlist.subscription_required || 'free';
        const userSub = req.user.subscription || 'free';
        
        // Check if user has access
        let hasAccess = false;
        if (required === 'free') {
            hasAccess = true; // Everyone can access free content
        } else if (required === 'lite') {
            hasAccess = userSub === 'lite' || userSub === 'premium';
        } else if (required === 'premium') {
            hasAccess = userSub === 'premium';
        }
        
        if (!hasAccess) {
            return res.status(403).json({ 
                error: `${required.charAt(0).toUpperCase() + required.slice(1)} subscription required to access this playlist.` 
            });
        }

        try {
            // Fetch M3U content from URL using native http/https
            const url = new URL(playlist.url);
            const protocol = url.protocol === 'https:' ? https : http;

            protocol.get(playlist.url, (response) => {
                let data = '';

                response.on('data', (chunk) => {
                    data += chunk;
                });

                response.on('end', () => {
                    res.json({
                        ...playlist,
                        content: data
                    });
                });
            }).on('error', (error) => {
                console.error('Error fetching playlist:', error);
                res.status(500).json({ error: 'Failed to fetch playlist content.' });
            });

        } catch (error) {
            console.error('Error:', error);
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

// ========================================
// SUBSCRIPTION & PAYMENT ENDPOINTS
// ========================================

// SUBSCRIPTION PLANS CONFIGURATION
const SUBSCRIPTION_PLANS = {
    free: {
        name: 'Free',
        price: 0,
        duration: null,
        features: [
            'Access to Free playlists only',
            'Standard streaming quality',
            'Limited channels',
            'Ads supported'
        ]
    },
    lite: {
        name: 'Lite',
        price: 2.50,
        duration: 30,
        features: [
            'Access to Free + Lite playlists',
            'HD streaming quality',
            'More channels',
            'No ads',
            'Email support'
        ]
    },
    premium: {
        name: 'Premium',
        price: 5.00,
        duration: 30,
        features: [
            'Access to ALL playlists',
            '4K streaming quality',
            'All channels',
            'No ads',
            'Priority support',
            'Multi-device access'
        ]
    }
};

// GET /api/plans - Get all subscription plans
app.get('/api/plans', (req, res) => {
    res.json(SUBSCRIPTION_PLANS);
});

// GET /api/me/subscription - Get current user's subscription details
app.get('/api/me/subscription', authenticateToken, (req, res) => {
    db.get(`
        SELECT 
            subscription_status,
            subscription_expires,
            created_at
        FROM users 
        WHERE id = ?
    `, [req.user.id], (err, subscription) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to get subscription details.' });
        }

        const plan = SUBSCRIPTION_PLANS[subscription.subscription_status] || SUBSCRIPTION_PLANS.free;
        
        res.json({
            current_plan: subscription.subscription_status,
            plan_details: plan,
            expires: subscription.subscription_expires,
            is_active: subscription.subscription_status === 'free' || 
                      (subscription.subscription_expires && new Date(subscription.subscription_expires) > new Date())
        });
    });
});

// POST /api/subscribe - Subscribe to a plan
app.post('/api/subscribe', authenticateToken, async (req, res) => {
    const { plan, payment_method } = req.body;

    if (!['lite', 'premium'].includes(plan)) {
        return res.status(400).json({ error: 'Invalid plan. Choose "lite" or "premium".' });
    }

    const planDetails = SUBSCRIPTION_PLANS[plan];
    const now = new Date();
    const expiryDate = new Date(now);
    expiryDate.setDate(expiryDate.getDate() + planDetails.duration);

    try {
        const transactionId = `TXN_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        // Record payment
        db.run(`
            INSERT INTO payments (user_id, amount, plan, payment_method, payment_status, transaction_id)
            VALUES (?, ?, ?, ?, 'completed', ?)
        `, [req.user.id, planDetails.price, plan, payment_method || 'card', transactionId], (err) => {
            if (err) {
                console.error('Payment recording error:', err);
                return res.status(500).json({ error: 'Failed to record payment.' });
            }

            // Update user subscription
            db.run(`
                UPDATE users 
                SET subscription_status = ?,
                    subscription_expires = ?
                WHERE id = ?
            `, [plan, expiryDate.toISOString(), req.user.id], (err) => {
                if (err) {
                    console.error('Subscription update error:', err);
                    return res.status(500).json({ error: 'Failed to update subscription.' });
                }

                res.json({
                    message: `Successfully subscribed to ${planDetails.name} plan!`,
                    subscription: {
                        plan: plan,
                        price: planDetails.price,
                        expires: expiryDate.toISOString(),
                        transaction_id: transactionId
                    }
                });
            });
        });

    } catch (error) {
        console.error('Subscription error:', error);
        res.status(500).json({ error: 'Failed to process subscription.' });
    }
});

// POST /api/cancel-subscription - Cancel subscription
app.post('/api/cancel-subscription', authenticateToken, (req, res) => {
    db.run(`
        UPDATE users 
        SET subscription_status = 'free',
            subscription_expires = NULL
        WHERE id = ?
    `, [req.user.id], (err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to cancel subscription.' });
        }

        res.json({ message: 'Subscription cancelled. You have been downgraded to Free plan.' });
    });
});

// GET /api/me/payments - Get user's payment history
app.get('/api/me/payments', authenticateToken, (req, res) => {
    db.all(`
        SELECT id, amount, plan, payment_method, payment_status, transaction_id, created_at
        FROM payments
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 50
    `, [req.user.id], (err, payments) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to get payment history.' });
        }

        res.json(payments);
    });
});

// ADMIN: GET /api/admin/subscriptions - Get subscription statistics
app.get('/api/admin/subscriptions', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required.' });
    }

    db.all(`
        SELECT 
            subscription_status as plan,
            COUNT(*) as count
        FROM users
        WHERE role != 'admin'
        GROUP BY subscription_status
    `, [], (err, stats) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to get subscription stats.' });
        }

        db.get(`
            SELECT 
                SUM(amount) as total_revenue,
                COUNT(*) as total_transactions,
                AVG(amount) as avg_transaction
            FROM payments
            WHERE payment_status = 'completed'
        `, [], (err, revenue) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to get revenue stats.' });
            }

            res.json({
                subscriptions: stats,
                revenue: revenue || { total_revenue: 0, total_transactions: 0, avg_transaction: 0 }
            });
        });
    });
});

// ADMIN: GET /api/admin/payments - Get all payments
app.get('/api/admin/payments', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required.' });
    }

    db.all(`
        SELECT 
            p.id,
            p.amount,
            p.plan,
            p.payment_method,
            p.payment_status,
            p.transaction_id,
            p.created_at,
            u.username,
            u.email
        FROM payments p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
        LIMIT 100
    `, [], (err, payments) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to get payments.' });
        }

        res.json(payments);
    });
});

// Cron job to expire subscriptions (runs every 24 hours)
setInterval(() => {
    db.run(`
        UPDATE users 
        SET subscription_status = 'free'
        WHERE subscription_status != 'free' 
        AND subscription_expires < datetime('now')
        AND role != 'admin'
    `, (err) => {
        if (!err) {
            console.log('✓ Checked and expired old subscriptions');
        }
    });
}, 24 * 60 * 60 * 1000);

// Start server
app.listen(PORT, () => {
    console.log(`\n🚀 StreamHub Server Running!`);
    console.log(`📍 http://localhost:${PORT}`);
    console.log(`\n👤 Default Admin Credentials:`);
    console.log(`   Username: admin`);
    console.log(`   Password: admin123\n`);
});

module.exports = app;
