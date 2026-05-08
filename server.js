require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const {
  DB_URL,
  DB_NAME,
  DB_COLLECTION,
  PORT,
  ADMIN_SETUP_CODE,
  JWT_SECRET,
  JWT_EXPIRES_IN,
} = process.env;

if (!DB_URL || !DB_NAME || !DB_COLLECTION || !ADMIN_SETUP_CODE || !JWT_SECRET) {
  console.error('Missing required env vars (DB_URL, DB_NAME, DB_COLLECTION, ADMIN_SETUP_CODE, JWT_SECRET)');
  process.exit(1);
}

const client = new MongoClient(DB_URL, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const app = express();

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
        return cb(null, true);
      }
      cb(new Error('Not allowed by CORS'));
    },
  }),
);

app.use(express.json());

let statsCollection;
let adminsCollection;

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/admin/register', async (req, res) => {
  try {
    const { code, username, password } = req.body || {};
    if (!code || !username || !password) {
      return res.status(400).json({ error: 'code, username and password required' });
    }
    if (code !== ADMIN_SETUP_CODE) {
      return res.status(403).json({ error: 'Invalid setup code' });
    }
    const existing = await adminsCollection.findOne({ username });
    if (existing) {
      return res.status(409).json({ error: 'Username already taken' });
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await adminsCollection.insertOne({
      username,
      passwordHash,
      createdAt: new Date(),
    });
    res.status(201).json({ _id: result.insertedId, username });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password required' });
    }
    const admin = await adminsCollection.findOne({ username });
    if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, admin.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign(
      { sub: admin._id.toString(), username: admin.username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN || '24h' },
    );
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/stats', requireAuth, async (req, res) => {
  try {
    const docs = await statsCollection.find({}).toArray();
    res.json(docs);
    console.log(`Admin ${req.admin.username} fetched all stats`);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/stats/:id', requireAuth, async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ error: 'Invalid id' });
    }
    const doc = await statsCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/stats', async (req, res) => {
  console.log('[POST /stats] origin=', req.headers.origin, 'body=', req.body);
  try {
    if (!req.body || typeof req.body !== 'object') {
      return res.status(400).json({ error: 'Body must be a JSON object' });
    }
    const result = await statsCollection.insertOne(req.body);
    console.log('[POST /stats] inserted', result.insertedId);
    res.status(201).json({ _id: result.insertedId, ...req.body });
  } catch (err) {
    console.error('[POST /stats] error', err);
    res.status(500).json({ error: err.message });
  }
});

async function start() {
  await client.connect();
  await client.db('admin').command({ ping: 1 });
  console.log('Connected to MongoDB');

  const statsDb = client.db(DB_NAME);
  const usersDb = client.db('users');
  statsCollection = statsDb.collection(DB_COLLECTION);
  adminsCollection = usersDb.collection('admin');

  await adminsCollection.createIndex({ username: 1 }, { unique: true });

  const port = PORT || 3000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

async function shutdown() {
  console.log('Shutting down...');
  await client.close();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
