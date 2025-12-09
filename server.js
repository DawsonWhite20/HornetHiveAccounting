require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const path = require('path');
const { supabase, signupUser, loginUserByUsername } = require('./auth'); // <- new import
const bcrypt = require('bcrypt');

const SALT_ROUNDS = 12;
const app = express();
const PORT = process.env.PORT || 3000;

// Serve static frontend
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'HornetHiveLogin.html'));
});

// Ultra-permissive CORS for dev
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,POST,PUT,PATCH,DELETE,OPTIONS'
  );
  res.setHeader(
    'Access-Control-Allow-Headers',
    req.header('Access-Control-Request-Headers') || 'Content-Type, Authorization'
  );
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// JSON body parsing
app.use(express.json());

// Simple request logger
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Supabase Admin client for privileged actions
const supabaseAdmin = require('@supabase/supabase-js').createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

// Health check
app.get('/health', (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

/* ===== ROUTES ===== */

// Signup
app.post('/api/signup', async (req, res) => {
  const user = req.body;
  try {
    const result = await signupUser(user); // <- use auth.js
    if (result.error) return res.status(400).json({ error: result.error });

    // Send approval email to admin
    const approveLink = `http://localhost:${PORT}/api/approve?email=${encodeURIComponent(user.email)}`;
    const rejectLink  = `http://localhost:${PORT}/api/reject?email=${encodeURIComponent(user.email)}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.ADMIN_EMAIL,
      subject: 'New User Signup Approval',
      text: `A new user signed up:\n\nName: ${user.first_name} ${user.last_name}\nEmail: ${user.email}\n\nApprove: ${approveLink}\nReject: ${rejectLink}\n`,
    });

    res.json({ message: 'Signup submitted! Waiting for admin approval.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Unexpected signup error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await loginUserByUsername(username, password); // <- use auth.js
    if (result.error) {
      const status = result.error.includes('approval') ? 403 : 401;
      return res.status(status).json({ error: result.error });
    }
    res.json({ user: result.user });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error logging in' });
  }
});

// Approve / Reject
app.get('/api/approve', async (req, res) => {
  const email = req.query.email;
  try {
    const { data, error } = await supabaseAdmin.from('users').update({ approved: true }).eq('email', email).select();
    if (error) return res.status(500).send('Failed to approve user');
    if (!data || data.length === 0) return res.status(404).send('User not found');

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your HornetHive account is approved!',
      text: 'You can now log in at http://127.0.0.1:5500/HornetHiveLogin.html',
    });

    res.send('User approved and notified!');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error approving user');
  }
});

app.get('/api/reject', async (req, res) => {
  const email = req.query.email;
  try {
    await supabaseAdmin.from('users').update({ approved: false }).eq('email', email);
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your HornetHive account was rejected',
      text: 'Sorry, your account was not approved.',
    });
    res.send('User rejected and notified!');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error rejecting user');
  }
});

// Catch-all 404
app.use((req, res) => {
  console.warn(`No route matched ${req.method} ${req.originalUrl}`);
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`HornetHive backend running on port ${PORT}`);
});
