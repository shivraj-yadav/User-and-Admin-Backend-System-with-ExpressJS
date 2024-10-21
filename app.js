// In app.js
const express = require('express');
const app = express();
const authRoutes = require('./routes/auth');

app.use(express.json());
app.use(express.static('public')); // Serve static files from the public folder
app.use('/auth', authRoutes);

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
