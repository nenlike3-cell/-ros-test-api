
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("Missing JWT_SECRET environment variable");
}

// Demo storage only: accounts disappear when the server restarts.
const users = [];

app.get("/", (req, res) => {
  res.json({
    name: "ROS Test Login API",
    status: "online",
    note: "Standalone test API, not an official ROS server"
  });
});

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      username.length < 3 ||
      username.length > 20 ||
      password.length < 8 ||
      password.length > 72
    ) {
      return res.status(400).json({
        error: "Username must be 3-20 characters and password 8-72 characters"
      });
    }

    const cleanName = username.trim().toLowerCase();

    if (users.some(user => user.username === cleanName)) {
      return res.status(409).json({
        error: "Username already exists"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    users.push({
      id: users.length + 1,
      username: cleanName,
      passwordHash
    });

    res.status(201).json({
      success: true,
      message: "Account created"
    });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Username and password are required"
      });
    }

    const user = users.find(
      item => item.username === username.trim().toLowerCase()
    );

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({
      success: true,
      token,
      username: user.username
    });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/me", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ")
    ? auth.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({ error: "Missing token" });
  }

  try {
    const data = jwt.verify(token, JWT_SECRET);

    res.json({
      success: true,
      userId: data.userId,
      username: data.username
    });
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Test API running on port ${PORT}`);
});
