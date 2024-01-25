import express from "express";
import bodyParser from "body-parser";
import pg from 'pg';
import bcrypt from 'bcrypt';
import session from 'express-session';
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
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
  res.render("secrets.ejs", {userSecret: req.user.secret});
  } else {
    res.redirect('/login');
  }
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect('/login');
  }
})

app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"],
}));

app.get("/auth/google/secrets", passport.authenticate("google", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect('/');
  })
});


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

app.post("/submit", async (req, res) => {
  let input = req.body.secret;
  let userEmail = req.user.email;
  try {
    await db.query("UPDATE users SET secret=$1 WHERE email=$2", [input, userEmail]);
    res.render('secrets.ejs', {userSecret: input});
  } catch(err) {
    console.log(err)
  }
})


passport.use("local", new Strategy( async function verify(username, password, cb) {
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

passport.use('google', new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
}, async (accessToken, refreshToken, profile, cb) => {
  console.log(profile);

  try {
    let result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email])
    if (result.rows.length === 0) {
      let newUser = await db.query(
        "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",[profile.email, "google"]
      );
      cb(null, newUser.rows[0]);
    } else {
      cb(null, result.rows[0]);
    }

  } catch(err) {
   cb(err);

  }
}))

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});