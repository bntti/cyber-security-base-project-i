import bodyParser from "body-parser";
import { randomBytes } from "crypto";
import express from "express";
import { engine } from "express-handlebars";
import session from "express-session";
import generator from "generate-password";
import sqlite3 from "sqlite3";

const app = express();
app.use(
  session({
    secret: generator.generate({ length: 64 }),
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.engine("handlebars", engine());
app.set("view engine", "handlebars");
app.set("views", "./src/views");

// Hash function and password checks
const xorSecret = randomBytes(256);
const hash = async (password) => {
  // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
  // return await argon.hash(req.body.newPassword, {
  //   type: argon.argon2id,
  //   memoryCost: 19456,
  //   parallelism: 1,
  //   timeCost: 2,
  // });

  const byteBuffer = Buffer.from(password);
  for (let i = 0; i < byteBuffer.length; i++) {
    const pos = i % xorSecret.length;
    byteBuffer[i] ^= xorSecret[pos];
  }
  return byteBuffer.toString("base64");
};

const checkPassword = async (password, pwdHash) => {
  // return await argon.verify(password.trim(), pwd_hash);
  return (await hash(password)) === pwdHash;
};

// DB init
const db = new sqlite3.Database(":memory:");
db.serialize(async () => {
  db.run(
    "CREATE TABLE users (username TEXT PRIMARY KEY, password TEXT NOT NULL, admin BOOLEAN)"
  );

  const adminPassword = generator.generate({ length: 32 });

  db.run(`INSERT INTO users(username, password, admin) VALUES (?, ?, ?)`, [
    "admin",
    await hash(adminPassword),
    true,
  ]);
});

// Views
app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, row) => {
      if (err) return console.error(err.message);

      if (row) {
        if (!(await checkPassword(password, row.password)))
          return res.render("login", { login: true, success: false });

        req.session.user = row;
        return res.redirect("/");
      }

      res.render("login", { login: true, success: false });
    }
  );
});

app.post("/register", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, row) => {
      if (err) return console.error(err.message);

      if (row) return res.render("login", { register: true, success: false });

      db.run(`INSERT INTO users(username, password, admin) VALUES (?, ?, ?)`, [
        username,
        await hash(password),
        false,
      ]);
      return res.render("login", { register: true, success: true });
    }
  );
});

//
app.get("/data", (req, res) => {
  db.all("SELECT * FROM your_table_name", [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
