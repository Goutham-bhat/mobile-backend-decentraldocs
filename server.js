require('dotenv').config();

const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const fsp = require('fs/promises');
const https = require('https');
const path = require('path');
const PinataClient = require('@pinata/sdk');

const app = express();
const port = process.env.PORT || 3000;

const pinataApiKey = process.env.PINATA_API_KEY;
const pinataSecretApiKey = process.env.PINATA_SECRET_API_KEY;

if (!pinataApiKey || !pinataSecretApiKey) {
    console.error("❌ Pinata API keys missing! Please set PINATA_API_KEY and PINATA_SECRET_API_KEY in your .env file.");
    process.exit(1);
}

const pinata = new PinataClient({
    pinataApiKey: pinataApiKey,
    pinataSecretApiKey: pinataSecretApiKey
});

pinata.testAuthentication().then((result) => {
    console.log("Pinata connection test result:", result);
}).catch((err) => {
    console.error("Pinata connection test failed:", err);
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const upload = multer({ dest: '/tmp/' });

app.get('/', (req, res) => {
    res.send('Decentral Docs Backend (Pinata IPFS Only) is running!');
});

app.post('/upload', upload.single('file'), async (req, res) => {
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
        console.log(`Attempting to pin ${req.file.originalname} to Pinata...`);
        const result = await pinata.pinFileToIPFS(readableStreamForFile, options);
        console.log("Pinata upload successful:", result.IpfsHash);

        await fsp.unlink(filePath);

        res.status(200).json({
            message: 'File uploaded to Pinata successfully!',
            IpfsHash: result.IpfsHash,
            PinSize: result.PinSize,
            Timestamp: result.Timestamp,
            isDuplicate: result.isDuplicate || false,
        });

    } catch (error) {
        console.error("Error uploading file to Pinata:", error);
        if (req.file?.path) {
            try {
                await fsp.unlink(filePath);
            } catch (cleanupErr) {
                console.error("Error cleaning up temporary file after failed upload:", cleanupErr);
            }
        }
        res.status(500).json({ error: 'Failed to upload file to Pinata.', details: error.message });
    }
});

app.get('/files', async (req, res) => {
    try {
        const result = await pinata.pinList({ status: 'pinned', pageLimit: 10 });
        res.json({ files: result.rows });
    } catch (err) {
        console.error('Error listing files:', err);
        res.status(500).json({ error: err.message || 'Failed to retrieve file list from Pinata.' });
    }
});

app.delete('/unpin/:hash', async (req, res) => {
    try {
        const ipfsHash = req.params.hash;
        console.log(`Attempting to unpin file with hash: ${ipfsHash}`);
        await pinata.unpin(ipfsHash);
        console.log(`File with hash ${ipfsHash} unpinned successfully.`);
        res.json({ success: true, message: `File with hash ${ipfsHash} unpinned.` });
    } catch (err) {
        console.error('Error unpinning file:', err);
        res.status(500).json({ error: err.message || `Failed to unpin file with hash ${req.params.hash}.` });
    }
});

app.get('/download/:hash', async (req, res) => {
    const hash = req.params.hash;
    const fileUrl = `https://gateway.pinata.cloud/ipfs/${hash}`;

    try {
        const { rows } = await pinata.pinList({ hashContains: hash, status: 'pinned', pageLimit: 1 });
        const originalName = rows[0]?.metadata?.name || hash;

        console.log(`Attempting to download file from IPFS: ${fileUrl}`);
        https.get(fileUrl, fileRes => {
            if (fileRes.statusCode !== 200) {
                console.error(`Gateway responded with status: ${fileRes.statusCode}`);
                return res.status(fileRes.statusCode).json({ error: `Failed to retrieve file from IPFS gateway (Status: ${fileRes.statusCode})` });
            }
            res.setHeader('Content-Disposition', `attachment; filename="${originalName}"`);
            fileRes.pipe(res);
        }).on('error', err => {
                console.error('Error during file download stream:', err);
                res.status(500).json({ error: 'Failed to download file from IPFS gateway due to stream error.' });
            });
    } catch (err) {
        console.error('Error fetching file metadata or initiating download:', err);
        res.status(500).json({ error: err.message || 'Failed to prepare file download.' });
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
    console.log(`Pinata status: ${pinataApiKey ? '✅ Ready' : '❌ Not configured'}`);
    console.log('--- Endpoints Ready ---');
    console.log(`GET /         : Health Check`);
    console.log(`POST /upload  : Upload a file to Pinata IPFS`);
    console.log(`GET /files    : List pinned files from Pinata`);
    console.log(`DELETE /unpin/:hash: Unpin a file from Pinata`);
    console.log(`GET /download/:hash: Download a file from IPFS via gateway`);
});