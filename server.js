const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();

// ================= DATABASE =================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ================= MIDDLEWARE =================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

app.use(session({
  secret: 'rcaSecret',
  resave: false,
  saveUninitialized: false
}));

// ================= AUTH MIDDLEWARE =================
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

// ================= LOGIN =================
app.post('/login', async (req, res) => {
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

  req.session.user = user;

  if (user.role === 'Admin') {
    return res.redirect('/admin.html');
  } else {
    return res.redirect('/dashboard.html');
  }
});

// ================= LOGOUT =================
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

// ================= GET ALL STUDENTS =================
app.get('/api/students', requireAdmin, async (req, res) => {
  const result = await pool.query(
    "SELECT id,name,email,mobile,isactive,sessionid FROM UserInformation WHERE role='Student' ORDER BY id DESC"
  );
  res.json(result.rows);
});

// ================= CREATE STUDENT =================
app.post('/api/students', requireAdmin, async (req, res) => {
  const { name, email, mobile, password, sessionid } = req.body;

  await pool.query(
    `INSERT INTO UserInformation
     (name,email,mobile,password,role,isactive,sessionid)
     VALUES($1,$2,$3,$4,'Student',true,$5)`,
    [name,email,mobile,password,sessionid]
  );

  res.json({ message: "Student Created" });
});

// ================= TOGGLE ACTIVE =================
app.put('/api/students/:id/toggle', requireAdmin, async (req, res) => {
  const id = req.params.id;

  await pool.query(
    "UPDATE UserInformation SET isactive = NOT isactive WHERE id=$1",
    [id]
  );

  res.json({ message: "Status Updated" });
});

// ================= RESET PASSWORD =================
app.put('/api/students/:id/reset', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const { newpassword } = req.body;

  await pool.query(
    "UPDATE UserInformation SET password=$1 WHERE id=$2",
    [newpassword, id]
  );

  res.json({ message: "Password Reset" });
});

// ================= PROTECTED PAGES =================
app.get('/admin.html', requireAdmin, (req, res) => {
  res.sendFile(__dirname + '/public/admin.html');
});

app.get('/dashboard.html', requireLogin, (req, res) => {
  res.sendFile(__dirname + '/public/dashboard.html');
});

// ================= START =================
app.listen(process.env.PORT || 3000, () => {
  console.log("Server Running...");
});
