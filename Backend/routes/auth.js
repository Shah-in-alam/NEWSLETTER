const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const app = express();
app.use(express.json()); // Make sure this is here to parse JSON requests

// Signup Route
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) return res.status(400).json({ msg: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user, saving the password hash in `passwordHash`
        const user = await prisma.user.create({
            data: { 
                username, 
                email, 
                passwordHash: hashedPassword,  // `passwordHash` instead of `password`
                createdAt: new Date()           // Make sure to set the `createdAt` field
            }
        });

        res.json({ msg: 'User registered successfully', user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Sign-in Route
app.post('/signin', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ msg: 'Email and password are required' });
    }

    try {
        const user = await prisma.user.findUnique({
            where: { email: email },
        });

        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        // Compare password with the hashed one in the database
        const isMatch = await bcrypt.compare(password, user.passwordHash);  // `passwordHash` instead of `password`
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || 'mySuperSecretKey123', { expiresIn: '1h' });

        res.json({ token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

module.exports = app;  // Export the auth routes to use in app.js
