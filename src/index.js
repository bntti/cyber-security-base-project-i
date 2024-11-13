import bodyParser from "body-parser";
import express from "express";
import { engine } from "express-handlebars";
import session from "express-session";
import generator from "generate-password";
import { addUser, checkPassword, getUser } from "./util.js";

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

// Views
app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  const user = await getUser(username);
  if (!user) return res.render("login", { loginFailed: true });

  if (!(await checkPassword(password, user.password)))
    return res.render("login", { loginFailed: true });

  req.session.user = user;
  return res.redirect("/");
});

app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  const user = await getUser(username);
  if (user) return res.render("login", { registerFailed: true });

  const newUser = await addUser(username, password, false);
  req.session.user = newUser;

  return res.redirect("/");
});

// Listen in port 3000
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
