require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const fsp = require('fs/promises');
const mongoose = require('mongoose');
const PinataClient = require('@pinata/sdk');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();
const port = process.env.PORT || 3000;
app.set('trust proxy', 1);

// ==============
// Env Validation
// ==============
const requiredEnvVars = ['PINATA_API_KEY', 'PINATA_SECRET_API_KEY', 'JWT_SECRET', 'MONGODB_URI'];
const missingVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingVars.length) {
  console.error(`❌ Missing env vars: ${missingVars.join(', ')}`);
  process.exit(1);
}

// ===============
// DB Setup
// ===============
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// ===============
// Rate Limiting
// ===============
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, try again later.'
});

// ===============
// Pinata Init
// ===============
const pinata = new PinataClient({
  pinataApiKey: process.env.PINATA_API_KEY,
  pinataSecretApiKey: process.env.PINATA_SECRET_API_KEY,
  timeout: 30000
});

pinata.testAuthentication()
  .then(() => console.log('✅ Pinata authentication successful'))
  .catch(err => {
    console.error('❌ Pinata authentication failed:', err);
    process.exit(1);
  });

// ===============
// Models
// ===============
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true, trim: true, minlength: 3, maxlength: 30 },
  password: { type: String, required: true, minlength: 8 }
}, { timestamps: true });

const fileSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    validate: {
      validator: v => mongoose.Types.ObjectId.isValid(v),
      message: props => `${props.value} is not a valid user ID!`
    }
  },
  ipfsHash: { type: String, required: true, unique: true },
  filename: { type: String, required: true },
  size: { type: Number, required: true },
  mimetype: String,
  pinStatus: { type: String, enum: ['pinned', 'unpinned'], default: 'pinned' },
  uploadedAt: { type: Date, default: Date.now }
}, { timestamps: true });

userSchema.index({ username: 1 });
fileSchema.index({ userId: 1 });
fileSchema.index({ ipfsHash: 1 });

const User = mongoose.model('User', userSchema);
const File = mongoose.model('File', fileSchema);

// ===============
// Middleware
// ===============
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGINS?.split(',') || '*',
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/auth', apiLimiter);

// ===============
// Multer Setup
// ===============
const upload = multer({
  dest: '/tmp/',
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const allowed = /\.(jpg|jpeg|png|gif|pdf|docx|txt|enc)$/i;
    if (!file.originalname.match(allowed)) {
      return cb(new Error('Unsupported file type'), false);
    }
    cb(null, true);
  }
});

// ===============
// JWT Helpers
// ===============
const generateToken = (user) => jwt.sign(
  { 
    userId: user._id.toString(),
    username: user.username 
  },
  process.env.JWT_SECRET,
  { expiresIn: '30m' } // ✅ CHANGED from '15m' to '30m'
);

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('JWT verification failed:', err);
      return res.status(403).json({ error: 'Token invalid or expired', code: 'TOKEN_EXPIRED' });
    }
    
    if (!mongoose.Types.ObjectId.isValid(decoded.userId)) {
      return res.status(403).json({ error: 'Invalid user ID in token' });
    }
    decoded.userId = new mongoose.Types.ObjectId(decoded.userId);
    
    console.log('Authenticated user:', { userId: decoded.userId, username: decoded.username });
    req.user = decoded;
    next();
  });
};

// ===============
// Routes
// ===============
app.get('/', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date(),
    services: {
      database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      pinata: 'active'
    }
  });
});

// --- Auth ---
app.post('/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ error: 'Username already exists' });

    const hash = await bcrypt.hash(password, 12);
    const newUser = await new User({ username, password: hash }).save();
    res.status(201).json({ message: 'User registered', userId: newUser._id });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    console.log('BODY:', req.body);
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: 'Invalid credentials' });

    const token = generateToken(user);
    res.json({ token, userId: user._id, username: user.username, expiresIn: 1800 });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- File Routes ---
app.post('/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const { path, originalname, mimetype, size } = req.file;
    const stream = fs.createReadStream(path);
    const pinataOptions = {
      pinataMetadata: {
        name: originalname,
        keyvalues: { 
          userId: req.user.userId.toString(),
          mimetype, 
          size,
          uploadedBy: req.user.username
        }
      },
      pinataOptions: { cidVersion: 0 }
    };

    const result = await pinata.pinFileToIPFS(stream, pinataOptions);
    const record = new File({
      userId: req.user.userId,
      ipfsHash: result.IpfsHash,
      filename: originalname,
      size,
      mimetype
    });
    await record.save();
    await fsp.unlink(path);

    res.status(201).json({
      success: true,
      ipfsHash: result.IpfsHash,
      pinSize: result.PinSize,
      timestamp: result.Timestamp,
      fileInfo: { name: originalname, size, type: mimetype }
    });
  } catch (err) {
    console.error('Upload error:', err);
    if (req.file?.path) {
      try { await fsp.unlink(req.file.path); } catch (_) {}
    }
    const status = err.message.includes('File too large') ? 413 : 500;
    res.status(status).json({ error: err.message || 'Upload failed' });
  }
});

app.get('/my-files', authenticateToken, async (req, res) => {
  console.log(`📥 GET /my-files called by user ${req.user.username} (${req.user.userId})`);
  try {
    const userId = req.user.userId;
    console.log('➡️ Fetching files for userId:', userId.toString());

    const files = await File.find({ userId }).sort({ createdAt: -1 }).lean();
    console.log(`🔍 Found ${files.length} files for user ${userId}:`);
    files.forEach(file => {
      console.log(`   🗂️ File ID: ${file._id}, Name: ${file.filename}, Hash: ${file.ipfsHash}`);
    });

    const invalidFiles = files.filter(f => !f.userId.equals(userId));
    if (invalidFiles.length > 0) {
      console.error('⚠️ SECURITY VIOLATION: Foreign files detected!', {
        expectedUser: userId,
        receivedFiles: invalidFiles.map(f => f._id)
      });
      return res.status(500).json({ error: 'Data integrity error' });
    }

    console.log('✅ Files validated, sending response');
    res.json({ files });
  } catch (err) {
    console.error('❌ File fetch error:', err);
    res.status(500).json({ error: 'Failed to retrieve files' });
  }
});

app.delete('/delete-file/:cid', authenticateToken, async (req, res) => {
  const { cid } = req.params;
  const userId = req.user.userId;

  if (!cid) return res.status(400).json({ error: 'CID is required' });

  try {
    const file = await File.findOneAndDelete({ ipfsHash: cid, userId });
    if (!file) return res.status(404).json({ error: 'File not found or not owned by user' });

    try {
      await pinata.unpin(cid);
      console.log(`📤 Unpinned ${cid} from Pinata`);
    } catch (pinErr) {
      console.warn(`⚠️ Failed to unpin ${cid} from Pinata:`, pinErr.message);
    }

    res.status(200).json({ message: 'File deleted successfully' });
  } catch (err) {
    console.error('❌ Delete error:', err);
    res.status(500).json({ error: 'Failed to delete file on server' });
  }
});

// --- Global Error ---
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal error' });
});

// --- Start ---
const server = app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// --- Graceful Shutdown ---
process.on('SIGTERM', async () => {
  console.log('👋 SIGTERM received, closing...');
  server.close(async () => {
    await mongoose.connection.close();
    console.log('🛑 MongoDB closed');
    process.exit(0);
  });
});
