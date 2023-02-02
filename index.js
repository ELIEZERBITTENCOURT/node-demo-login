const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const mysql = require("mysql2");

const secret = "secret_key";
const saltRounds = 10;

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "test"
});

const login = (username, password) => {
  return new Promise((resolve, reject) => {
    connection.query(
      "SELECT * FROM users WHERE username = ?",
      [username],
      (error, results) => {
        if (error) reject(error);
        if (results.length === 0) {
          reject({ error: "Invalid login" });
        } else {
          const user = results[0];
          bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
              const token = jwt.sign({ username }, secret, { expiresIn: "1h" });
              resolve({ token });
            } else {
              reject({ error: "Invalid login" });
            }
          });
        }
      }
    );
  });
};

const verifyToken = token => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, secret, (error, decoded) => {
      if (error) reject({ error: "Invalid token" });
      resolve(decoded);
    });
  });
};

const validateInput = ({ username, password }) => {
  if (!username || !password) {
    return { error: "Invalid input" };
  }
  return {};
};

const register = ({ username, password }) => {
  return new Promise((resolve, reject) => {
    const validationResult = validateInput({ username, password });
    if (validationResult.error) {
      reject(validationResult);
    } else {
      bcrypt.hash(password, saltRounds, (error, hash) => {
        if (error) reject(error);
        connection.query(
          "INSERT INTO users (username, password) VALUES (?,?)",
          [username, hash],
          (error, results) => {
            if (error) reject(error);
            resolve({ message: "User registered" });
          }
        );
      });
    }
  });
};

module.exports = { login, verifyToken, register };
