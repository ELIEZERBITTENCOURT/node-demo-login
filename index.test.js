const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const mysql = require("mysql2");
const { login, verifyToken, register } = require("./index");

describe("Login", () => {
  const username = "user1";
  const password = "password1";

  beforeAll(async () => {
    connection.query("INSERT INTO users (username, password) VALUES (?,?)", [      username,      await bcrypt.hash(password, saltRounds)    ]);
  });

  afterAll(async () => {
    connection.query("DELETE FROM users WHERE username = ?", [username]);
  });

  it("should return a token if the login is successful", async () => {
    const result = await login(username, password);
    expect(result).toHaveProperty("token");
  });

  it("should return an error if the login is unsuccessful", async () => {
    try {
      await login(username, "wrongPassword");
    } catch (error) {
      expect(error).toHaveProperty("error", "Invalid login");
    }
  });
});

describe("Verify Token", () => {
  it("should return the decoded token if the token is valid", async () => {
    const token = jwt.sign({ username: "user1" }, secret, { expiresIn: "1h" });
    const decoded = await verifyToken(token);
    expect(decoded).toHaveProperty("username", "user1");
  });

  it("should return an error if the token is invalid", async () => {
    try {
      await verifyToken("invalidToken");
    } catch (error) {
      expect(error).toHaveProperty("error", "Invalid token");
    }
  });
});

describe("Register", () => {
  const username = "user2";
  const password = "password2";

  afterAll(async () => {
    connection.query("DELETE FROM users WHERE username = ?", [username]);
  });

  it("should return a message if the registration is successful", async () => {
    const result = await register({ username, password });
    expect(result).toHaveProperty("message", "User registered");
  });

  it("should return an error if the input is invalid", async () => {
    try {
      await register({});
    } catch (error) {
      expect(error).toHaveProperty("error", "Invalid input");
    }
  });
});
