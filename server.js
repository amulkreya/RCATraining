const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();

// ===============================
// DATABASE CONNECTION
// ===============================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// ===============================
// MIDDLEWARE
// ===============================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

app.use(session({
  secret: 'rcaTrainingSecret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// ===============================
// AUTH MIDDLEWARE
// ===============================
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'Admin') {
    return res.send("Access Denied");
  }
  next();
}

// ===============================
// LOGIN ROUTE
// ===============================
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.send("Email and Password required.");
    }

    const result = await pool.query(
      "SELECT * FROM UserInformation WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.send("User not found.");
    }

    const user = result.rows[0];

    if (!user.isactive) {
      return res.send("User is inactive. Contact Admin.");
    }

    if (password !== user.password) {
      return res.send("Invalid password.");
    }

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    };

    if (user.role === "Admin") {
      return res.redirect('/admin.html');
    } else {
      return res.redirect('/dashboard.html');
    }

  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

// ===============================
// LOGOUT
// ===============================
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

// ===============================
// PROTECTED ROUTES
// ===============================
app.get('/admin.html', requireAdmin, (req, res) => {
  res.sendFile(__dirname + '/public/admin.html');
});

app.get('/dashboard.html', requireLogin, (req, res) => {
  res.sendFile(__dirname + '/public/dashboard.html');
});

// ===============================
// START SERVER
// ===============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("RCA Training Platform Running on Port " + PORT);
});
