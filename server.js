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

const app = express();
const port = process.env.PORT || 3000;

// Load env variables
const pinataApiKey = process.env.PINATA_API_KEY;
const pinataSecretApiKey = process.env.PINATA_SECRET_API_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const mongoUri = process.env.MONGODB_URI;

if (!pinataApiKey || !pinataSecretApiKey) {
    console.error("❌ Pinata API keys missing! Please set PINATA_API_KEY and PINATA_SECRET_API_KEY in your .env file.");
    process.exit(1);
}

if (!mongoUri) {
    console.error("❌ MongoDB URI missing! Please set MONGODB_URI in your .env file.");
    process.exit(1);
}

// Connect to MongoDB Atlas
mongoose.connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('✅ Connected to MongoDB Atlas'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
});

// Define User schema/model
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
});
const User = mongoose.model('User', userSchema);

// Define File schema/model
const fileSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    ipfsHash: String,
    filename: String,
    uploadedAt: { type: Date, default: Date.now },
});
const File = mongoose.model('File', fileSchema);

// Initialize Pinata client
const pinata = new PinataClient({
    pinataApiKey,
    pinataSecretApiKey
});

pinata.testAuthentication()
    .then(() => console.log('✅ Pinata authentication successful'))
    .catch(err => {
        console.error('❌ Pinata authentication failed:', err);
        process.exit(1);
    });

// Middleware
app.use(cors()); // backend-only; no origin restrictions needed
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer({ dest: '/tmp/' });

// JWT Auth Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Missing token' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

// Routes
app.get('/', (req, res) => {
    res.send('✅ Decentral Docs Backend is running (Pinata IPFS only)');
});

// Register
app.post('/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    try {
        if (await User.findOne({ username })) {
            return res.status(409).json({ error: 'User already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login
app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    try {
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id, username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Upload
app.post('/upload', authenticateToken, upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }

    const filePath = req.file.path;
    const readableStreamForFile = fs.createReadStream(filePath);
    const options = {
        pinataMetadata: {
            name: req.file.originalname,
        },
    };

    try {
        const result = await pinata.pinFileToIPFS(readableStreamForFile, options);
        const newFile = new File({
            userId: req.user.userId,
            ipfsHash: result.IpfsHash,
            filename: req.file.originalname,
        });
        await newFile.save();

        await fsp.unlink(filePath);

        res.status(200).json({
            message: 'File uploaded to Pinata successfully!',
            IpfsHash: result.IpfsHash,
            PinSize: result.PinSize,
            Timestamp: result.Timestamp,
            isDuplicate: result.isDuplicate || false,
        });
    } catch (error) {
        console.error("Pinata upload error:", error);
        if (req.file?.path) {
            try {
                await fsp.unlink(filePath);
            } catch (cleanupErr) {
                console.error("Cleanup error:", cleanupErr);
            }
        }
        res.status(500).json({ error: 'Failed to upload file to Pinata.' });
    }
});

// List files
app.get('/files', authenticateToken, async (req, res) => {
    try {
        const userFiles = await File.find({ userId: req.user.userId }).select('-__v');
        res.json({ files: userFiles });
    } catch (err) {
        console.error('Fetch files error:', err);
        res.status(500).json({ error: 'Failed to retrieve files' });
    }
});

// Unpin
app.delete('/unpin/:hash', authenticateToken, async (req, res) => {
    const ipfsHash = req.params.hash;

    try {
        const file = await File.findOneAndDelete({ userId: req.user.userId, ipfsHash });
        if (!file) return res.status(404).json({ error: 'File not found' });

        await pinata.unpin(ipfsHash);
        res.json({ success: true, message: `File with hash ${ipfsHash} unpinned and deleted.` });
    } catch (err) {
        console.error('Unpin error:', err);
        res.status(500).json({ error: 'Failed to unpin file' });
    }
});

// Download
app.get('/download/:hash', authenticateToken, async (req, res) => {
    const hash = req.params.hash;
    const fileUrl = `https://gateway.pinata.cloud/ipfs/${hash}`;

    try {
        const file = await File.findOne({ userId: req.user.userId, ipfsHash: hash });
        const originalName = file?.filename || hash;

        https.get(fileUrl, fileRes => {
            if (fileRes.statusCode !== 200) {
                return res.status(fileRes.statusCode).json({ error: `Failed to retrieve file (Status: ${fileRes.statusCode})` });
            }
            res.setHeader('Content-Disposition', `attachment; filename="${originalName}"`);
            fileRes.pipe(res);
        }).on('error', err => {
            console.error('Download error:', err);
            res.status(500).json({ error: 'Failed to download file.' });
        });
    } catch (err) {
        console.error('Preparation error:', err);
        res.status(500).json({ error: 'Failed to prepare download.' });
    }
});

// Start server
app.listen(port, () => {
    console.log(`🚀 Server live on port ${port}`);
    console.log(`Pinata status: ${pinataApiKey ? '✅ Ready' : '❌ Not configured'}`);
    console.log(`Available endpoints:
    - GET    /                (Health check)
    - POST   /auth/register   (Register)
    - POST   /auth/login      (Login)
    - POST   /upload          (Upload file)
    - GET    /files           (List files)
    - GET    /download/:hash  (Download file)
    - DELETE /unpin/:hash     (Unpin file)`);
});
