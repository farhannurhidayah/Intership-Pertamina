const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
require('dotenv').config();

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET;

const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.sendStatus(401); // Unauthorized jika token tidak ada

  jwt.verify(token, JWT_SECRET, async (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        // Tangani error kedaluwarsa token dengan pesan khusus
        return res.status(401).json({ message: 'Token telah kedaluwarsa. Silakan login kembali.' });
      } else {
        // Error lain (misalnya token tidak valid)
        return res.sendStatus(403); // Forbidden
      }
    }

    req.user = user;
    next();
  });
};

module.exports = authenticateJWT;
