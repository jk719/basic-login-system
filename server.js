const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const session = require('express-session');
const pool = require('./database');
const path = require('path');

const app = express();

// Middlewares
app.use(express.static('public'));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: 'secret key',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
  function(username, password, done) {
    pool.query('SELECT id, username, password FROM users WHERE username = $1', [username], (err, result) => {
      if (err) return done(err);
      const user = result.rows[0];
      if (!user) return done(null, false);
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) return done(err);
        if (isMatch) return done(null, { id: user.id, username: user.username });
        else return done(null, false);
      });
    });
  }
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  pool.query('SELECT id, username FROM users WHERE id = $1', [id], (err, result) => {
    if (err) return done(err);
    const user = result.rows[0];
    if (!user) return done(null, false);
    return done(null, user);
  });
});

// Changed this from '/login' to '/'
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/'
}));

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  pool.query('INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id', [username, hash], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Server Error");
    }
    res.redirect('/');
  });
});

app.get('/dashboard', (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`Welcome, ${req.user.username}!`);
  } else {
    res.redirect('/');
  }
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.listen(3000, () => {
  console.log('Server started on http://localhost:3000');
});
