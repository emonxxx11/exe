const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const https = require('https');
const http = require('http');

const app = express();
const PORT = 3000; // Fixed port for Railway

// GitHub configuration
const GITHUB_REPO_URL = 'https://github.com/emonxxx11/exe/raw/main/EMON%20XTIER%20BYPASS.exe';
const GITHUB_API_URL = 'https://api.github.com/repos/emonxxx11/exe/contents/EMON%20XTIER%20BYPASS.exe';
const CACHE_DURATION = 30 * 60 * 1000; // 30 minutes cache

// Cache for GitHub file info
let fileCache = {
    data: null,
    lastFetch: 0,
    hash: null
};

// Security and rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Download rate limiter (more restrictive)
const downloadLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 5, // limit each IP to 5 downloads per minute
    message: {
        error: 'Too many download attempts, please try again later.',
        retryAfter: '1 minute'
    }
});

// Middleware
app.use(cors({
    origin: '*', // Allow all origins
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));
app.use(limiter);

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Serve static files from uploads directory
app.use('/downloads', express.static(uploadsDir));

// Root endpoint - Simple and fast response for Railway health checks
app.get('/', (req, res) => {
    res.status(200).json({
        message: 'Emon Xiter Server v2.0.0',
        status: 'online',
        timestamp: new Date().toISOString(),
        version: '2.0.0'
    });
});

// Favicon handler to prevent 404s
app.get('/favicon.ico', (req, res) => {
    res.status(204).end(); // No content
});

// File validation and security
const ALLOWED_EXTENSIONS = ['.exe', '.dll'];
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

function validateFile(filePath) {
    try {
        if (!fs.existsSync(filePath)) {
            return { valid: false, error: 'File not found' };
        }

        const stats = fs.statSync(filePath);
        
        // Check file size
        if (stats.size > MAX_FILE_SIZE) {
            return { valid: false, error: 'File too large' };
        }

        // Check file extension
        const ext = path.extname(filePath).toLowerCase();
        if (!ALLOWED_EXTENSIONS.includes(ext)) {
            return { valid: false, error: 'Invalid file type' };
        }

        // Basic file integrity check (not empty)
        if (stats.size === 0) {
            return { valid: false, error: 'File is empty' };
        }

        return { valid: true, stats };
    } catch (error) {
        return { valid: false, error: 'File validation failed' };
    }
}

function calculateFileHash(filePath) {
    try {
        const fileBuffer = fs.readFileSync(filePath);
        return crypto.createHash('sha256').update(fileBuffer).digest('hex');
    } catch (error) {
        return null;
    }
}

// GitHub API functions
function fetchFromGitHub(url) {
    return new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http;
        
        const req = client.get(url, {
            headers: {
                'User-Agent': 'Emon-Xiter-Server/2.0.0',
                'Accept': 'application/vnd.github.v3+json'
            }
        }, (res) => {
            let data = '';
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                if (res.statusCode === 200) {
                    resolve(data);
                } else {
                    reject(new Error(`GitHub API returned status: ${res.statusCode}`));
                }
            });
        });
        
        req.on('error', (error) => {
            reject(error);
        });
        
        req.setTimeout(15000, () => {
            req.destroy();
            reject(new Error('GitHub API timeout'));
        });
    });
}

async function getGitHubFileInfo() {
    try {
        // Check cache first
        const now = Date.now();
        if (fileCache.data && (now - fileCache.lastFetch) < CACHE_DURATION) {
            return fileCache.data;
        }
        
        console.log('Fetching file info from GitHub...');
        const response = await fetchFromGitHub(GITHUB_API_URL);
        const fileInfo = JSON.parse(response);
        
        // Update cache
        fileCache.data = {
            downloadUrl: GITHUB_REPO_URL,
            filename: 'EMON XTIER BYPASS.exe',
            size: fileInfo.size,
            lastModified: new Date(fileInfo.last_modified || fileInfo.updated_at),
            version: '1.0.0',
            checksum: {
                algorithm: 'SHA256',
                value: fileInfo.sha
            },
            metadata: {
                serverVersion: '2.0.0',
                source: 'GitHub',
                repository: 'emonxxx11/exe',
                timestamp: new Date().toISOString(),
                expiresAt: new Date(now + CACHE_DURATION).toISOString()
            }
        };
        fileCache.lastFetch = now;
        fileCache.hash = fileInfo.sha;
        
        console.log(`GitHub file info cached: ${fileInfo.size} bytes, SHA: ${fileInfo.sha.substring(0, 16)}...`);
        return fileCache.data;
        
    } catch (error) {
        console.error('Failed to fetch GitHub file info:', error.message);
        
        // Return cached data if available, even if expired
        if (fileCache.data) {
            console.log('Using expired cache data');
            return fileCache.data;
        }
        
        throw error;
    }
}

async function proxyDownloadFromGitHub(res) {
    try {
        console.log('Proxying download from GitHub...');
        
        const client = GITHUB_REPO_URL.startsWith('https') ? https : http;
        
        const req = client.get(GITHUB_REPO_URL, {
            headers: {
                'User-Agent': 'Emon-Xiter-Server/2.0.0'
            }
        }, (githubRes) => {
            // Set security headers
            res.setHeader('Content-Disposition', 'attachment; filename="EMON XTIER BYPASS.exe"');
            res.setHeader('Content-Type', 'application/octet-stream');
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.setHeader('X-Frame-Options', 'DENY');
            res.setHeader('Content-Length', githubRes.headers['content-length']);
            
            // Pipe the response
            githubRes.pipe(res);
            
            githubRes.on('error', (error) => {
                console.error('GitHub download error:', error);
                if (!res.headersSent) {
                    res.status(500).json({ 
                        error: 'Download failed',
                        message: 'Failed to download from GitHub',
                        timestamp: new Date().toISOString()
                    });
                }
            });
        });
        
        req.on('error', (error) => {
            console.error('GitHub request error:', error);
            if (!res.headersSent) {
                res.status(500).json({ 
                    error: 'Download failed',
                    message: 'Failed to connect to GitHub',
                    timestamp: new Date().toISOString()
                });
            }
        });
        
        req.setTimeout(30000, () => {
            req.destroy();
            if (!res.headersSent) {
                res.status(500).json({ 
                    error: 'Download timeout',
                    message: 'GitHub download timed out',
                    timestamp: new Date().toISOString()
                });
            }
        });
        
    } catch (error) {
        console.error('Proxy download error:', error);
        if (!res.headersSent) {
            res.status(500).json({ 
                error: 'Download failed',
                message: 'Failed to proxy download from GitHub',
                timestamp: new Date().toISOString()
            });
        }
    }
}

// Logging middleware
function logRequest(req, res, next) {
    const timestamp = new Date().toISOString();
    const ip = req.ip || req.connection.remoteAddress;
    console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${ip} - User-Agent: ${req.get('User-Agent') || 'Unknown'}`);
    next();
}

app.use(logRequest);

// Health check endpoint with detailed status
app.get('/health', async (req, res) => {
    const uptime = process.uptime();
    const memoryUsage = process.memoryUsage();
    const exePath = path.join(uploadsDir, 'main.exe');
    const fileStatus = validateFile(exePath);
    
    // Check GitHub connectivity
    let githubStatus = 'Unknown';
    try {
        await getGitHubFileInfo();
        githubStatus = 'Available';
    } catch (error) {
        githubStatus = 'Unavailable';
    }
    
    res.json({ 
        status: 'OK', 
        message: 'Emon Xiter Server is running',
        timestamp: new Date().toISOString(),
        uptime: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`,
        memory: {
            used: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
            total: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`
        },
        sources: {
            github: {
                status: githubStatus,
                repository: 'emonxxx11/exe',
                url: GITHUB_REPO_URL
            },
            local: {
                exists: fileStatus.valid,
                status: fileStatus.valid ? 'Ready' : 'Not available'
            }
        },
        version: '2.0.0'
    });
});

// Get main executable download link with enhanced info
app.get('/api/download/main-exe', async (req, res) => {
    try {
        // Try to get file info from GitHub first
        try {
            const githubInfo = await getGitHubFileInfo();
            const downloadUrl = `${req.protocol}://${req.get('host')}/downloads/main.exe`;
            
            res.json({
                downloadUrl: downloadUrl,
                filename: githubInfo.filename,
                size: githubInfo.size,
                lastModified: githubInfo.lastModified,
                version: githubInfo.version,
                checksum: githubInfo.checksum,
                metadata: {
                    ...githubInfo.metadata,
                    serverUrl: `${req.protocol}://${req.get('host')}`,
                    timestamp: new Date().toISOString()
                }
            });
            return;
        } catch (githubError) {
            console.log('GitHub unavailable, falling back to local file...');
        }
        
        // Fallback to local file if GitHub is unavailable
        const exePath = path.join(uploadsDir, 'main.exe');
        const fileStatus = validateFile(exePath);
        
        if (!fileStatus.valid) {
            return res.status(404).json({ 
                error: 'Main executable not found or invalid',
                message: fileStatus.error,
                timestamp: new Date().toISOString()
            });
        }
        
        const stats = fileStatus.stats;
        const downloadUrl = `${req.protocol}://${req.get('host')}/downloads/main.exe`;
        const fileHash = calculateFileHash(exePath);
        
        res.json({
            downloadUrl: downloadUrl,
            filename: 'main.exe',
            size: stats.size,
            lastModified: stats.mtime,
            version: '1.0.0',
            checksum: {
                algorithm: 'SHA256',
                value: fileHash
            },
            metadata: {
                serverVersion: '2.0.0',
                source: 'Local',
                timestamp: new Date().toISOString(),
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
            }
        });
    } catch (error) {
        console.error('Error in download info endpoint:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: 'Failed to get download information',
            timestamp: new Date().toISOString()
        });
    }
});

// Download the main executable directly with rate limiting
app.get('/downloads/main.exe', downloadLimiter, async (req, res) => {
    try {
        // Log download attempt
        const ip = req.ip || req.connection.remoteAddress;
        console.log(`[DOWNLOAD] ${ip} requesting download`);
        
        // Try to proxy from GitHub first
        try {
            await proxyDownloadFromGitHub(res);
            console.log(`[DOWNLOAD] Success: ${ip} completed GitHub download`);
            return;
        } catch (githubError) {
            console.log('GitHub download failed, falling back to local file...');
        }
        
        // Fallback to local file if GitHub is unavailable
        const exePath = path.join(uploadsDir, 'main.exe');
        const fileStatus = validateFile(exePath);
        
        if (!fileStatus.valid) {
            return res.status(404).json({ 
                error: 'Main executable not found or invalid',
                message: fileStatus.error,
                timestamp: new Date().toISOString()
            });
        }
        
        // Set security headers
        res.setHeader('Content-Disposition', 'attachment; filename="main.exe"');
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        
        console.log(`[DOWNLOAD] ${ip} downloading local main.exe (${fileStatus.stats.size} bytes)`);
        
        res.download(exePath, 'main.exe', (err) => {
            if (err) {
                console.error('Download error:', err);
                if (!res.headersSent) {
                    res.status(500).json({ 
                        error: 'Download failed',
                        message: err.message,
                        timestamp: new Date().toISOString()
                    });
                }
            } else {
                console.log(`[DOWNLOAD] Success: ${ip} completed local download`);
            }
        });
    } catch (error) {
        console.error('Download endpoint error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: 'Download failed',
            timestamp: new Date().toISOString()
        });
    }
});

// Upload main executable (enhanced with validation)
app.post('/api/upload/main-exe', (req, res) => {
    try {
        // This is a placeholder - in production you'd implement actual file upload
        res.json({ 
            message: 'Upload endpoint ready',
            note: 'Upload the main.exe file to the uploads/ directory',
            requirements: {
                maxSize: '100MB',
                allowedTypes: ALLOWED_EXTENSIONS,
                validation: 'SHA256 checksum verification'
            },
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Upload endpoint error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: 'Upload endpoint failed',
            timestamp: new Date().toISOString()
        });
    }
});

// File verification endpoint
app.post('/api/verify/:filename', (req, res) => {
    try {
        const filename = req.params.filename;
        const filePath = path.join(uploadsDir, filename);
        const fileStatus = validateFile(filePath);
        
        if (!fileStatus.valid) {
            return res.status(404).json({
                valid: false,
                error: fileStatus.error,
                timestamp: new Date().toISOString()
            });
        }
        
        const fileHash = calculateFileHash(filePath);
        
        res.json({
            valid: true,
            filename: filename,
            size: fileStatus.stats.size,
            checksum: {
                algorithm: 'SHA256',
                value: fileHash
            },
            lastModified: fileStatus.stats.mtime,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Verification endpoint error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: 'File verification failed',
            timestamp: new Date().toISOString()
        });
    }
});

// Server statistics endpoint
app.get('/api/stats', (req, res) => {
    try {
        const uptime = process.uptime();
        const memoryUsage = process.memoryUsage();
        const exePath = path.join(uploadsDir, 'main.exe');
        const fileStatus = validateFile(exePath);
        
        res.json({
            server: {
                uptime: uptime,
                memory: memoryUsage,
                version: '2.0.0',
                nodeVersion: process.version
            },
            files: {
                mainExe: {
                    exists: fileStatus.valid,
                    size: fileStatus.valid ? fileStatus.stats.size : 0,
                    lastModified: fileStatus.valid ? fileStatus.stats.mtime : null
                }
            },
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Stats endpoint error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: 'Failed to get server statistics',
            timestamp: new Date().toISOString()
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message,
        timestamp: new Date().toISOString()
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Endpoint not found',
        message: `The endpoint ${req.method} ${req.path} does not exist`,
        availableEndpoints: [
            'GET /health',
            'GET /api/info',
            'GET /api/download/main-exe',
            'GET /downloads/main.exe',
            'POST /api/upload/main-exe',
            'POST /api/verify/:filename',
            'GET /api/stats'
        ],
        timestamp: new Date().toISOString()
    });
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully');
    process.exit(0);
});

// Catch-all error handler to prevent 502s
app.use((err, req, res, next) => {
    console.error('❌ Unhandled error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: 'Something went wrong',
        timestamp: new Date().toISOString()
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Not found',
        message: `Route ${req.path} not found`,
        timestamp: new Date().toISOString()
    });
});

// Start server with proper error handling
console.log('🚀 Starting Emon Xiter Server...');
console.log(`📡 Attempting to bind to port: ${PORT}`);

const server = app.listen(PORT, '0.0.0.0', (err) => {
    if (err) {
        console.error('❌ Failed to start server:', err);
        process.exit(1);
    }
    
    console.log('='.repeat(60));
    console.log('🚀 Emon Xiter Server v2.0.0');
    console.log('='.repeat(60));
    console.log(`📡 Server running on port: ${PORT} (Fixed)`);
    console.log(`🌍 Host: 0.0.0.0 (all interfaces)`);
    console.log(`📁 Uploads directory: ${uploadsDir}`);
    console.log(`🐙 GitHub integration: ${GITHUB_REPO_URL}`);
    console.log(`🌐 Health check: http://localhost:${PORT}/health`);
    console.log(`📥 Download endpoint: http://localhost:${PORT}/api/download/main-exe`);
    console.log(`📊 Stats endpoint: http://localhost:${PORT}/api/stats`);
    console.log(`🔒 Rate limiting: Enabled (100 req/15min, 5 downloads/min)`);
    console.log(`💾 Cache duration: ${CACHE_DURATION / 60000} minutes`);
    console.log(`⚙️ Environment: Self-contained (no env vars needed)`);
    console.log('='.repeat(60));
    console.log('✅ Server started successfully!');
    console.log('🔍 Ready to handle requests...');
});

// Handle server errors
server.on('error', (error) => {
    console.error('❌ Server error:', error);
    if (error.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use`);
        process.exit(1);
    } else {
        console.error('❌ Unexpected server error:', error.message);
        process.exit(1);
    }
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});
