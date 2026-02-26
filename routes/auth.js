
const express = require('express');
const router = express.Router();
const pool = require('../db');
const bcrypt = require('bcrypt');

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query(
    "SELECT * FROM UserInformation WHERE email=$1",
    [email]
  );

  if (result.rows.length === 0) return res.send("User not found");

  const user = result.rows[0];

  if (!user.isactive) return res.send("User inactive");

  const match = await bcrypt.compare(password, user.password);

  if (!match) return res.send("Invalid password");

  req.session.user = user;

  if (user.role === "Admin") {
    res.redirect('/admin.html');
  } else {
    res.redirect('/dashboard.html');
  }
});

module.exports = router;
