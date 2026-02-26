
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const pool = require('./db');
require('dotenv').config();

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session'
  }),
  secret: 'rcaSecretKey',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.use('/auth', require('./routes/auth'));
app.use('/admin', require('./routes/admin'));
app.use('/student', require('./routes/student'));

app.listen(process.env.PORT || 3000, () => {
  console.log("Server started...");
});
