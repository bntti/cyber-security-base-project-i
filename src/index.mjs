import bodyParser from "body-parser";
import express from "express";
import { engine } from "express-handlebars";
import session from "express-session";
import generator from "generate-password";
// import { RateLimiterMemory } from "rate-limiter-flexible";
import { addUser, checkPassword, findUser, FLAG, getUser } from "./util.mjs";

const app = express();

// Middleware
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

app.use(express.static("./")); // Should be removed

// const rateLimiter = new RateLimiterMemory({
//   points: 6,
//   duration: 1,
//   blockDuration: 5,
// });
// app.use((req, res, next) => {
//   rateLimiter
//     .consume(req.ip)
//     .then(() => next())
//     .catch(() => res.status(429).send());
// });

// Views
app.get("/", (req, res) => {
  let admin = false;
  if (req.session.user && req.session.user.admin) admin = true;

  res.render("home", { admin: admin, flag: FLAG });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/users", (req, res) => {
  if (!req.session.user) return res.redirect("/login");
  if (!req.session.user.username.startsWith("admin")) return res.redirect("/");

  // if (!req.session.user.admin)
  //   return res.redirect("/login");

  res.render("users");
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  const user = await getUser(username);
  if (!user) return res.status(401).render("login", { loginFailed: true });

  if (!(await checkPassword(password, user.password)))
    return res.status(401).render("login", { loginFailed: true });

  req.session.user = user;
  return res.redirect("/");
});

app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // After fixes this would not be unnecessary
  if (username.startsWith("admin"))
    return res.status(400).render("login", { registerFailed: true });

  const user = await getUser(username);
  if (user) return res.status(400).render("login", { registerFailed: true });

  const newUser = await addUser(username, password, false);
  req.session.user = newUser;

  return res.redirect("/");
});

app.post("/users", async (req, res) => {
  if (!req.session.user) return res.redirect("/login");
  if (!req.session.user.username.startsWith("admin")) return res.redirect("/");

  const search = req.body.search;
  const result = await findUser(search);

  res.render("users", { result: result, noResult: result === null });
});

// Listen in port 3000
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
