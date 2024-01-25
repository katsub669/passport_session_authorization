import express from "express";
import bodyParser from "body-parser";
import pg from 'pg';
import bcrypt from 'bcrypt';
import session from 'express-session';
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";


const app = express();
const port = 3000;
const saltRounds = 10; 
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
  }
})
);

app.use(passport.initialize());
app.use(passport.session());


const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PW,
  port: process.env.DB_PORT,
});
db.connect();


app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {

  res.render("register.ejs");
});

app.get("/secrets", (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
  res.render("secrets.ejs");
  } else {
    res.redirect('/login');
  }
})

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const pw = req.body.password;
  let search = await db.query('SELECT * FROM users WHERE email =$1', [email]);
  if (search.rows.length > 0) {
    res.send('User already exists');
  } else {
    //PW hashing
    bcrypt.hash(pw, saltRounds, async (err, hash) => {
      if (err) {
        console.log(err);
        res.send('error:(', err)
      }
      let result = await db.query(
        "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",[email, hash]
      );
      let user = result.rows[0];
      req.login(user, (err) => {
        console.log(err)
        res.redirect("/secrets");
      });
    })
  }
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
})
);

passport.use(new Strategy( async function verify(username, password, cb) {
  try {
    let searchResult = await db.query('SELECT * from users WHERE email=$1', [username]);
    let user = searchResult.rows[0];
    let dbPw = user.password;

    if (dbPw) {
      bcrypt.compare(password, dbPw, (err, result) => {
        if (err) {
          return cb(err);
        } else {
          if (result) {
            return cb(null, user);
          } else {
            return cb(null, false);
          }
        }
      })

    } else {
      return cb("User not found");
    }

  } catch(err){
    return cb(err);
  }
}));

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});