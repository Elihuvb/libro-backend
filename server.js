// server.js
require("dotenv").config();
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const app = express();
const PORT = process.env.PORT || 3000;

const db = new Database("db.sqlite");
const SECRET = process.env.JWT_SECRET || "dev_secret";

app.use(cors());
app.use(express.json());

// Init tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    post_id INTEGER,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(post_id) REFERENCES posts(id)
  );
`);

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const payload = jwt.verify(token, SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    const stmt = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    const result = stmt.run(username, hash);
    res.json({ id: result.lastInsertRowid });
  } catch {
    res.status(400).json({ error: "Username already exists" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const stmt = db.prepare("SELECT * FROM users WHERE username = ?");
  const user = stmt.get(username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const token = jwt.sign({ id: user.id }, SECRET);
  res.json({ token });
});

app.delete("/user", authMiddleware, (req, res) => {
  const userId = req.user.id;
  db.prepare("DELETE FROM users WHERE id = ?").run(userId);
  db.prepare("DELETE FROM posts WHERE user_id = ?").run(userId);
  db.prepare("DELETE FROM comments WHERE user_id = ?").run(userId);
  res.json({ success: true });
});

app.post("/posts", authMiddleware, (req, res) => {
  const { content } = req.body;
  try {
    const stmt = db.prepare("INSERT INTO posts (user_id, content) VALUES (?, ?)");
    const result = stmt.run(req.user.id, content);
    res.json({ post_id: result.lastInsertRowid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/posts/:id", authMiddleware, (req, res) => {
  const postId = req.params.id;
  const post = db.prepare("SELECT * FROM posts WHERE id = ?").get(postId);
  if (!post || post.user_id !== req.user.id) {
    return res.status(403).json({ error: "Unauthorized" });
  }
  db.prepare("DELETE FROM posts WHERE id = ?").run(postId);
  db.prepare("DELETE FROM comments WHERE post_id = ?").run(postId);
  res.json({ success: true });
});

app.get("/posts", (req, res) => {
  const rows = db.prepare("SELECT id, user_id, content, created_at FROM posts ORDER BY created_at DESC").all();
  res.json(rows);
});

app.post("/posts/:id/comments", authMiddleware, (req, res) => {
  const { content } = req.body;
  const postId = req.params.id;
  try {
    const stmt = db.prepare("INSERT INTO comments (user_id, post_id, content) VALUES (?, ?, ?)");
    const result = stmt.run(req.user.id, postId, content);
    res.json({ comment_id: result.lastInsertRowid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/posts/:id/comments", (req, res) => {
  const postId = req.params.id;
  const rows = db.prepare("SELECT id, user_id, content, created_at FROM comments WHERE post_id = ? ORDER BY created_at ASC").all(postId);
  res.json(rows);
});

app.delete("/comments/:id", authMiddleware, (req, res) => {
  const commentId = req.params.id;
  const comment = db.prepare("SELECT * FROM comments WHERE id = ?").get(commentId);
  if (!comment || comment.user_id !== req.user.id) {
    return res.status(403).json({ error: "Unauthorized" });
  }
  db.prepare("DELETE FROM comments WHERE id = ?").run(commentId);
  res.json({ success: true });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));