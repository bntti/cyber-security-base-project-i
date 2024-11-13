import { randomBytes } from "crypto";
import generator from "generate-password";
import sqlite3 from "sqlite3";

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

export const checkPassword = async (password, pwdHash) => {
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

// DB functions
export const getUser = async (username) =>
  new Promise((resolve, reject) => {
    db.get(
      "SELECT * FROM users WHERE username = ?",
      [username],
      async (err, row) => {
        if (err) {
          console.error(err.message);
          return reject();
        }

        return row ? resolve(row) : resolve(null);
      }
    );
  });

export const addUser = async (username, password, admin) =>
  new Promise(async (resolve, reject) => {
    db.run(
      `INSERT INTO users(username, password, admin) VALUES (?, ?, ?)`,
      [username, await hash(password), false],
      async (err) => {
        if (err) {
          console.error(err.message);
          return reject();
        }

        resolve(await getUser(username));
      }
    );
  });
