const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Database setup
const db = new sqlite3.Database('./messages.db', (err) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Connected to SQLite database');
});

// Initialize database schema
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      public_key TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS conversations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user1_id INTEGER NOT NULL,
      user2_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user1_id) REFERENCES users(id),
      FOREIGN KEY(user2_id) REFERENCES users(id),
      UNIQUE(user1_id, user2_id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id INTEGER NOT NULL,
      sender_id INTEGER NOT NULL,
      encrypted_content TEXT NOT NULL,
      nonce TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(conversation_id) REFERENCES conversations(id),
      FOREIGN KEY(sender_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT UNIQUE NOT NULL,
      public_key TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

// Helper: Run promise-based db queries
const dbRun = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ id: this.lastID, changes: this.changes });
    });
  });
};

const dbGet = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

const dbAll = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

// Auth middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    req.username = decoded.username;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Routes

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, publicKey } = req.body;
    if (!username || !password || !publicKey) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await dbRun(
      'INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)',
      [username, hashedPassword, publicKey]
    );

    res.json({ success: true, message: 'User registered' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password, publicKey } = req.body;
    
    const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    await dbRun(
      'INSERT INTO sessions (user_id, token, public_key) VALUES (?, ?, ?)',
      [user.id, token, publicKey]
    );

    res.json({ 
      token, 
      userId: user.id,
      username: user.username
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get users
app.get('/api/users', verifyToken, async (req, res) => {
  try {
    const users = await dbAll('SELECT id, username, public_key FROM users WHERE id != ?', [req.userId]);
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get conversations
app.get('/api/conversations', verifyToken, async (req, res) => {
  try {
    const conversations = await dbAll(`
      SELECT DISTINCT c.id, u.id as user_id, u.username, u.public_key
      FROM conversations c
      JOIN users u ON (u.id = c.user1_id OR u.id = c.user2_id)
      WHERE (c.user1_id = ? OR c.user2_id = ?) AND u.id != ?
      ORDER BY c.id DESC
    `, [req.userId, req.userId, req.userId]);
    res.json(conversations);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get messages for conversation
app.get('/api/conversations/:conversationId/messages', verifyToken, async (req, res) => {
  try {
    const messages = await dbAll(`
      SELECT m.*, u.username FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE m.conversation_id = ?
      ORDER BY m.created_at ASC
    `, [req.params.conversationId]);
    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start server
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// WebSocket handling
const connectedClients = new Map();

wss.on('connection', (ws, req) => {
  const token = new URL(`http://localhost${req.url}`).searchParams.get('token');
  
  if (!token) {
    ws.close();
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.id;
    
    if (!connectedClients.has(userId)) {
      connectedClients.set(userId, []);
    }
    connectedClients.get(userId).push(ws);

    ws.on('message', async (data) => {
      try {
        const message = JSON.parse(data);
        
        if (message.type === 'send_message') {
          // Create or get conversation
          let conversation = await dbGet(`
            SELECT id FROM conversations 
            WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
          `, [userId, message.recipientId, message.recipientId, userId]);

          if (!conversation) {
            const result = await dbRun(`
              INSERT INTO conversations (user1_id, user2_id) VALUES (?, ?)
            `, [Math.min(userId, message.recipientId), Math.max(userId, message.recipientId)]);
            conversation = { id: result.id };
          }

          // Store encrypted message
          await dbRun(`
            INSERT INTO messages (conversation_id, sender_id, encrypted_content, nonce)
            VALUES (?, ?, ?, ?)
          `, [conversation.id, userId, message.encryptedContent, message.nonce]);

          // Send to recipient if online
          if (connectedClients.has(message.recipientId)) {
            const recipientWs = connectedClients.get(message.recipientId)[0];
            if (recipientWs.readyState === WebSocket.OPEN) {
              recipientWs.send(JSON.stringify({
                type: 'new_message',
                senderId: userId,
                encryptedContent: message.encryptedContent,
                nonce: message.nonce,
                conversationId: conversation.id
              }));
            }
          }
        }
      } catch (err) {
        console.error('WebSocket error:', err);
      }
    });

    ws.on('close', () => {
      const userWss = connectedClients.get(userId);
      if (userWss) {
        const index = userWss.indexOf(ws);
        if (index > -1) userWss.splice(index, 1);
      }
    });
  } catch (err) {
    ws.close();
  }
});

module.exports = { app, server };