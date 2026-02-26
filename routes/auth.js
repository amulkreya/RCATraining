const express = require('express');
const router = express.Router();
const pool = require('../db');

// ======================
// LOGIN LOGIC
// ======================
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
      return res.send("Email and Password are required.");
    }

    // Find user
    const result = await pool.query(
      "SELECT * FROM UserInformation WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.send("User not found.");
    }

    const user = result.rows[0];

    // Check active status
    if (!user.isactive) {
      return res.send("Your account is inactive. Contact Admin.");
    }

    // Plain text password check
    if (password !== user.password) {
      return res.send("Invalid password.");
    }

    // Store session
    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    };

    // Role based redirect
    if (user.role === "Admin") {
      return res.redirect('/admin.html');
    } else {
      return res.redirect('/dashboard.html');
    }

  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).send("Internal Server Error");
  }
});

// ======================
// LOGOUT
// ======================
router.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

module.exports = router;
