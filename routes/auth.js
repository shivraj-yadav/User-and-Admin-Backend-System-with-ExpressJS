const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const router = express.Router();

// MySQL connection setup
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', // your MySQL username
    password: '', // your MySQL password
    database: 'demo_db' // your database name
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed: ' + err.stack);
        return;
    }
    console.log('Connected to MySQL database.');
});

// In auth.js
router.get('/findUser/:id', (req, res) => {
    const userId = req.params.id;

    // SQL query to find user by ID
    const query = 'SELECT * FROM users WHERE id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Database query failed' });
        }

        if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    });
});



// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // 'Bearer TOKEN'

    if (!token) return res.status(401).send('Access Denied');

    jwt.verify(token, 'secretKey', (err, user) => { // Replace 'secretKey' with your secret key
        if (err) return res.status(403).send('Invalid Token');
        req.user = user; // Add user info to request object
        next();
    });
}

// Signup route
router.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    db.query(query, [username, email, hashedPassword], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Server error');
        }
        res.status(201).send('User registered successfully!');
    });
});

// Signin route
router.post('/signin', (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Server error');
        }
        if (results.length === 0) {
            return res.status(401).send('Invalid email or password');
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).send('Invalid email or password');
        }

        const token = jwt.sign({ userId: user.id }, 'secretKey', { expiresIn: '1h' }); // replace 'secretKey' with your secret key
        res.json({ message: 'Logged in successfully', token });
    });
});

// Update user profile route (protected)
router.put('/update', authenticateToken, async (req, res) => {
    const { username, email, password } = req.body;
    const userId = req.user.userId; // Extract userId from JWT token

    let query = 'UPDATE users SET ';
    const params = [];

    if (username) {
        query += 'username = ?, ';
        params.push(username);
    }
    if (email) {
        query += 'email = ?, ';
        params.push(email);
    }
    if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        query += 'password = ?, ';
        params.push(hashedPassword);
    }

    query = query.slice(0, -2) + ' WHERE id = ?'; // Remove the trailing comma and add WHERE clause
    params.push(userId);

    db.query(query, params, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Server error');
        }
        res.status(200).send('User profile updated successfully!');
    });
});

// Middleware to check if the user is an admin
const isAdmin = (req, res, next) => {
    // Implement your actual admin check here
    const user = req.user; // Assuming user data is stored in req.user
    if (user && user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
};


router.get('/findUser/:id', (req, res) => {
    const userId = req.params.id;
    const query = 'SELECT * FROM users WHERE id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Database query failed' });
        }
        if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    });
});

router.get('/users', (req, res) => {
    const sql = 'SELECT * FROM users';
    db.query(sql, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});


// DELETE /auth/users/:id
router.delete('/users/:id', (req, res) => {
    const userId = req.params.id;

    // SQL query to delete the user
    const query = 'DELETE FROM users WHERE id = ?';

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error deleting user:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        // Check if a row was affected
        if (results.affectedRows > 0) {
            res.status(200).json({ message: 'User deleted successfully' });
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    });
});



module.exports = router;





