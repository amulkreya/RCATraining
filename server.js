const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();

/* ================= DATABASE ================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* ================= MIDDLEWARE ================= */

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serve only public assets (login.html allowed)
app.use(express.static('public'));

app.use(session({
  secret: 'rcaSecret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false
  }
}));

/* ================= AUTH MIDDLEWARE ================= */

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'Admin') {
    return res.redirect('/login.html');
  }
  next();
}

/* ================= LOGIN ================= */

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM UserInformation WHERE email=$1",
      [email]
    );

    if (result.rows.length === 0)
      return res.send("User not found");

    const user = result.rows[0];

    if (!user.isactive)
      return res.send("User inactive");

    if (password !== user.password)
      return res.send("Invalid password");

    // Store only required info
    req.session.user = {
      id: user.id,
      role: user.role,
      name: user.name
    };

    if (user.role === 'Admin') {
      return res.redirect('/admin');
    } else {
      return res.redirect('/dashboard');
    }

  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

/* ================= LOGOUT ================= */

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

/* ================= PROTECTED PAGES ================= */

// IMPORTANT: No .html here

app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(__dirname + '/public/admin.html');
});

app.get('/dashboard', requireLogin, (req, res) => {
  res.sendFile(__dirname + '/public/dashboard.html');
});

/* ================= STUDENT APIs ================= */

// Get all students
app.get('/api/students', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id,name,email,mobile,isactive,sessionid FROM UserInformation WHERE role='Student' ORDER BY id DESC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error fetching students");
  }
});

// Create student
app.post('/api/students', requireAdmin, async (req, res) => {
  try {
    const { name, email, mobile, password, sessionid } = req.body;

    await pool.query(
      `INSERT INTO UserInformation
       (name,email,mobile,password,role,isactive,sessionid)
       VALUES($1,$2,$3,$4,'Student',true,$5)`,
      [name,email,mobile,password,sessionid]
    );

    res.json({ message: "Student Created" });

  } catch (err) {
    console.error(err);
    res.status(500).send("Error creating student");
  }
});

// Toggle active/inactive
app.put('/api/students/:id/toggle', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;

    await pool.query(
      "UPDATE UserInformation SET isactive = NOT isactive WHERE id=$1",
      [id]
    );

    res.json({ message: "Status Updated" });

  } catch (err) {
    console.error(err);
    res.status(500).send("Error updating status");
  }
});

// Reset password
app.put('/api/students/:id/reset', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { newpassword } = req.body;

    await pool.query(
      "UPDATE UserInformation SET password=$1 WHERE id=$2",
      [newpassword, id]
    );

    res.json({ message: "Password Reset Successful" });

  } catch (err) {
    console.error(err);
    res.status(500).send("Error resetting password");
  }
});

/* ================= START SERVER ================= */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("🚀 RCA Training Platform Running on Port " + PORT);
});
