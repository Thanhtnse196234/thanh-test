const express = require("express");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

dotenv.config();

const app = express();
app.use(express.json());

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_MINUTES = 10;

const users = [
  {
    id: "u_001",
    username: "admin@kitchen.com",
    passwordHash: bcrypt.hashSync("123456", 10),
    enabled: true,
    failedAttempts: 0,
    lockedUntil: null,
    role: "admin",
    name: "Admin",
  },
];

function getAccountStatus(user) {
  const now = Date.now();
  const lockedUntilMs = user.lockedUntil ? new Date(user.lockedUntil).getTime() : 0;

  if (lockedUntilMs && lockedUntilMs > now) return "Locked";
  if (!user.enabled) return "Inactive";
  return "Active";
}

function validateLoginInput(username, password) {
  if (!username || !password) return "Thiếu username hoặc password.";
  if (typeof username !== "string" || typeof password !== "string") return "Dữ liệu không hợp lệ.";
  if (username.trim().length < 3) return "Username quá ngắn.";
  if (password.length < 6) return "Password phải có ít nhất 6 ký tự.";
  return null;
}

app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};

  const inputErr = validateLoginInput(username, password);
  if (inputErr) {
    return res.status(400).json({
      message: inputErr,
      status: "Login Failed",
    });
  }

  const user = users.find(
    (u) => u.username.toLowerCase() === username.trim().toLowerCase()
  );

  if (!user) {
    return res.status(401).json({
      message: "Sai tài khoản hoặc mật khẩu.",
      status: "Login Failed",
    });
  }

  if (!user.enabled) {
    return res.status(403).json({
      message: "Tài khoản không ở trạng thái Active.",
      status: "Locked",
    });
  }

  const now = Date.now();
  if (user.lockedUntil && new Date(user.lockedUntil).getTime() > now) {
    const remainMs = new Date(user.lockedUntil).getTime() - now;
    const remainSec = Math.ceil(remainMs / 1000);

    return res.status(423).json({
      message: `Tài khoản đang bị khóa tạm thời. Thử lại sau ${remainSec} giây.`,
      status: "Locked",
    });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);

  if (!ok) {
    user.failedAttempts += 1;

    if (user.failedAttempts >= MAX_FAILED_ATTEMPTS) {
      const lockedUntil = new Date(Date.now() + LOCK_MINUTES * 60 * 1000);
      user.lockedUntil = lockedUntil.toISOString();

      return res.status(423).json({
        message: `Bạn đã nhập sai quá ${MAX_FAILED_ATTEMPTS} lần. Tài khoản bị khóa ${LOCK_MINUTES} phút.`,
        status: "Locked",
        failedAttempts: user.failedAttempts,
        lockedUntil: user.lockedUntil,
      });
    }

    return res.status(401).json({
      message: "Sai tài khoản hoặc mật khẩu.",
      status: "Login Failed",
      failedAttempts: user.failedAttempts,
      remainingAttempts: MAX_FAILED_ATTEMPTS - user.failedAttempts,
    });
  }

  user.failedAttempts = 0;
  user.lockedUntil = null;

  if (!process.env.JWT_ACCESS_SECRET) {
    return res.status(500).json({ message: "JWT_ACCESS_SECRET chưa set trong .env" });
  }

  const accessToken = jwt.sign(
    { sub: user.id, role: user.role },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.ACCESS_EXPIRES_IN || "15m" }
  );

  return res.json({
    message: "Đăng nhập thành công.",
    status: "Active",
    accessToken,
    user: { id: user.id, username: user.username, role: user.role, name: user.name },
  });
});

app.get("/api/debug/users", (req, res) => {
  res.json(users.map(u => ({
    username: u.username,
    enabled: u.enabled,
    failedAttempts: u.failedAttempts,
    lockedUntil: u.lockedUntil,
    accountStatus: getAccountStatus(u),
  })));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running: http://localhost:${PORT}`));
