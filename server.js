require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const fsp = require('fs/promises');
const https = require('https');
const mongoose = require('mongoose');
const PinataClient = require('@pinata/sdk');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');

const app = express();
const port = process.env.PORT || 3000;

// Enhanced environment validation
const requiredEnvVars = [
  'PINATA_API_KEY',
  'PINATA_SECRET_API_KEY',
  'JWT_SECRET',
  'MONGODB_URI'
];

const missingVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingVars.length > 0) {
  console.error(`❌ Missing required environment variables: ${missingVars.join(', ')}`);
  process.exit(1);
}

// Database connection with improved settings
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000
})
.then(() => console.log('✅ Connected to MongoDB Atlas'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// Enhanced rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

// Models with validation and indexes
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    unique: true,
    required: true,
    minlength: 3,
    maxlength: 30
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
}, { timestamps: true });

const fileSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    required: true
  },
  ipfsHash: {
    type: String,
    required: true,
    unique: true
  },
  filename: {
    type: String,
    required: true
  },
  size: {
    type: Number,
    required: true
  },
  mimetype: String
}, { timestamps: true });

// Add indexes for better query performance
fileSchema.index({ userId: 1 });
fileSchema.index({ ipfsHash: 1 });

const User = mongoose.model('User', userSchema);
const File = mongoose.model('File', fileSchema);

// Initialize Pinata with timeout
const pinata = new PinataClient({
  pinataApiKey: process.env.PINATA_API_KEY,
  pinataSecretApiKey: process.env.PINATA_SECRET_API_KEY,
  timeout: 30000 // 30 seconds timeout
});

// Enhanced authentication test
async function verifyPinataConnection() {
  try {
    await pinata.testAuthentication();
    console.log('✅ Pinata authentication successful');
  } catch (err) {
    console.error('❌ Pinata authentication failed:', err.message);
    process.exit(1);
  }
}
verifyPinataConnection();

// Middleware stack
app.use(cors({
  origin: process.env.CORS_ORIGINS?.split(',') || '*',
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(apiLimiter);

// Configure multer with file size limits
const upload = multer({
  dest: '/tmp/',
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 1
  },
  fileFilter: (req, file, cb) => {
    if (!file.originalname.match(/\.(jpg|jpeg|png|gif|pdf|docx|txt)$/i)) {
      return cb(new Error('Only certain file types are allowed!'), false);
    }
    cb(null, true);
  }
});

// Enhanced JWT middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Authorization token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      const message = err.name === 'TokenExpiredError' ? 
        'Token expired' : 'Invalid token';
      return res.status(403).json({ error: message });
    }
    
    req.user = {
      userId: decoded.userId,
      username: decoded.username
    };
    next();
  });
}

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ 
    status: 'healthy',
    services: {
      database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      pinata: 'active'
    },
    timestamp: new Date()
  });
});

// Enhanced auth routes
app.post('/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ 
      message: 'User registered successfully',
      userId: newUser._id
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ 
      token,
      expiresIn: 3600,
      userId: user._id
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Enhanced upload endpoint
app.post('/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { path, originalname, mimetype, size } = req.file;
    const readableStream = fs.createReadStream(path);

    const pinataOptions = {
      pinataMetadata: {
        name: originalname,
        keyvalues: {
          userId: req.user.userId,
          mimetype,
          size
        }
      },
      pinataOptions: {
        cidVersion: 0
      }
    };

    const pinataResponse = await pinata.pinFileToIPFS(readableStream, pinataOptions);
    
    const fileRecord = new File({
      userId: req.user.userId,
      ipfsHash: pinataResponse.IpfsHash,
      filename: originalname,
      size,
      mimetype
    });
    
    await fileRecord.save();
    await fsp.unlink(path);

    res.status(201).json({
      success: true,
      ipfsHash: pinataResponse.IpfsHash,
      pinSize: pinataResponse.PinSize,
      timestamp: pinataResponse.Timestamp,
      fileInfo: {
        name: originalname,
        size,
        type: mimetype
      }
    });
  } catch (err) {
    console.error('Upload error:', err);
    
    if (req.file?.path) {
      try {
        await fsp.unlink(req.file.path);
      } catch (cleanupErr) {
        console.error('File cleanup error:', cleanupErr);
      }
    }

    const statusCode = err.message.includes('File too large') ? 413 : 500;
    res.status(statusCode).json({ 
      error: err.message || 'File upload failed' 
    });
  }
});

// Additional endpoints with improved error handling
app.get('/files', authenticateToken, async (req, res) => {
  try {
    const files = await File.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .select('filename ipfsHash size mimetype createdAt');
    
    res.json({ files });
  } catch (err) {
    console.error('File list error:', err);
    res.status(500).json({ error: 'Failed to retrieve files' });
  }
});

app.get('/files/:hash', authenticateToken, async (req, res) => {
  try {
    const file = await File.findOne({ 
      userId: req.user.userId,
      ipfsHash: req.params.hash
    });
    
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    res.json({ file });
  } catch (err) {
    console.error('File details error:', err);
    res.status(500).json({ error: 'Failed to retrieve file details' });
  }
});

app.delete('/files/:hash', authenticateToken, async (req, res) => {
  try {
    const file = await File.findOneAndDelete({ 
      userId: req.user.userId,
      ipfsHash: req.params.hash
    });
    
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    await pinata.unpin(file.ipfsHash);
    res.json({ success: true, message: 'File unpinned successfully' });
  } catch (err) {
    console.error('Unpin error:', err);
    res.status(500).json({ error: 'Failed to unpin file' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server with graceful shutdown
const server = app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});