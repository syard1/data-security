const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const cryptoService = require('../services/cryptoService');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'secure-messaging-secret-change-in-production';
const USERS_FILE = path.join(__dirname, '../data/users.json');

let users = [];
let activeSessions = new Map();
let temporaryKeys = new Map();

function ensureDataDirectory() {
    const dataDir = path.join(__dirname, '../data');
    if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
    }
}

function loadUsers() {
    try {
        if (fs.existsSync(USERS_FILE)) {
            const data = fs.readFileSync(USERS_FILE, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error('❌ Error loading users:', error);
    }
    return [];
}

function saveUsers() {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    } catch (error) {
        console.error('❌ Error saving users:', error);
    }
}

async function hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
}

function generateJWT(userId, username) {
    return jwt.sign(
        { userId, username, iat: Date.now() },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
}

function verifyJWT(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

function getClientIp(req) {
    return req.headers['x-forwarded-for'] || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress || 
           req.ip || 
           'unknown';
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false,
            message: 'Access denied - No token provided',
            alert: {
                type: 'AUTHENTICATION_FAILURE',
                description: 'No token provided'
            }
        });
    }

    const decoded = verifyJWT(token);
    if (!decoded) {
        return res.status(403).json({ 
            success: false,
            message: 'Invalid or expired token',
            alert: {
                type: 'AUTHENTICATION_FAILURE',
                description: 'Token expired or invalid'
            }
        });
    }

    req.user = decoded;
    next();
}

async function register(req, res) {
    try {
        const { username, password, email } = req.body;
        const clientIp = getClientIp(req);

        if (!username || !password || !email) {
            return res.status(400).json({ 
                success: false, 
                message: 'All fields are required' 
            });
        }

        if (password.length < 1) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password is required' 
            });
        }

        if (users.find(user => user.username === username || user.email === email)) {
            return res.status(400).json({ 
                success: false, 
                message: 'User already exists' 
            });
        }

        const hashedPasswordValue = await hashPassword(password);
        const userId = uuidv4();

        const newUser = {
            id: userId,
            username,
            email,
            password: hashedPasswordValue,
            createdAt: new Date().toISOString(),
            lastLogin: null
        };

        users.push(newUser);
        saveUsers();

        console.log(`✅ New user registered: ${username} from ${clientIp}`);

        res.json({ 
            success: true, 
            message: 'User registered successfully', 
            userId 
        });

    } catch (error) {
        console.error('❌ Registration error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Registration failed' 
        });
    }
}

async function keyExchange(req, res) {
    try {
        const { clientPublicKey } = req.body;
        const clientIp = getClientIp(req);

        if (!clientPublicKey) {
            return res.status(400).json({ 
                success: false, 
                message: 'Client public key required' 
            });
        }

        const sessionId = uuidv4();
        storeTemporaryKey(sessionId, { clientPublicKey, stage: 'TLS_HANDSHAKE_REQUIRED' });

        console.log(`🔑 TLS handshake required for authentication - Session: ${sessionId} - Client: ${clientIp}`);

        res.json({
            success: true,
            sessionId: sessionId,
            tlsHandshakeRequired: true,
            message: 'Complete TLS handshake before authentication',
            serverPublicKey: cryptoService.getServerPublicKey(),
            serverCertificate: cryptoService.getServerCertificate()
        });

    } catch (error) {
        console.error('❌ Auth initiation error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Authentication initiation failed' 
        });
    }
}

async function login(req, res) {
    try {
        const { sessionId, encryptedCredentials, iv, tlsSessionId } = req.body;
        const clientIp = getClientIp(req);

        if (!sessionId || !encryptedCredentials || !iv || !tlsSessionId) {
            return res.status(400).json({ 
                success: false, 
                message: 'Session ID, TLS session ID, encrypted credentials, and IV required' 
            });
        }

        const tlsSessionKey = cryptoService.getSessionKey(tlsSessionId);
        if (!tlsSessionKey) {
            return res.status(400).json({ 
                success: false, 
                message: 'TLS handshake must be completed before authentication' 
            });
        }

        const authSessionData = getTemporaryKey(sessionId);
        if (!authSessionData || !authSessionData.stage || authSessionData.stage !== 'TLS_HANDSHAKE_REQUIRED') {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid auth session or expired' 
            });
        }

        const sessionKey = tlsSessionKey;
        
        const decryptedCredentials = cryptoService.aesDecrypt(encryptedCredentials, sessionKey, iv);
        const { username, password } = JSON.parse(decryptedCredentials);

        const user = users.find(u => u.username === username);
        if (!user) {
            removeTemporaryKey(sessionId);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        const isValidPassword = await verifyPassword(password, user.password);
        if (!isValidPassword) {
            removeTemporaryKey(sessionId);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        const token = generateJWT(user.id, user.username);
        const newSessionId = uuidv4();
        
        const sessionAesKey = sessionKey; // Use the key derived from TLS handshake
        
        activeSessions.set(newSessionId, {
            userId: user.id,
            username: user.username,
            startTime: new Date(),
            aesSymmetricKey: sessionAesKey,
            tlsSessionId: tlsSessionId,
            clientIp: clientIp
        });

        user.lastLogin = new Date().toISOString();
        saveUsers();

        removeTemporaryKey(sessionId);

        console.log(`🔐 Secure login successful (using TLS session key): ${username} from ${clientIp}`);

        res.json({
            success: true,
            message: 'Login successful with TLS session key',
            token,
            sessionId: newSessionId,
            tlsSessionId: tlsSessionId,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                aesSymmetricKey: sessionAesKey
            }
        });

    } catch (error) {
        console.error('❌ Secure login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Secure login failed' 
        });
    }
}

function logout(req, res) {
    try {
        const { sessionId } = req.body;
        const clientIp = getClientIp(req);

        if (sessionId) {
            const session = activeSessions.get(sessionId);
            if (session) {
                console.log(`👋 User ${session.username} logged out from ${clientIp}`);
            }
            activeSessions.delete(sessionId);
            cryptoService.removeSessionKey(sessionId);
        }

        res.json({ 
            success: true, 
            message: 'Logged out successfully' 
        });

    } catch (error) {
        console.error('❌ Logout error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Logout failed' 
        });
    }
}

function storeTemporaryKey(sessionId, aesKey) {
    const expiration = Date.now() + (5 * 60 * 1000); // 5 minutes
    temporaryKeys.set(sessionId, { key: aesKey, expires: expiration });
    
    cleanupExpiredKeys();
}

function getTemporaryKey(sessionId) {
    const keyData = temporaryKeys.get(sessionId);
    if (!keyData) return null;
    
    if (Date.now() > keyData.expires) {
        temporaryKeys.delete(sessionId);
        return null;
    }
    
    return keyData.key;
}

function removeTemporaryKey(sessionId) {
    temporaryKeys.delete(sessionId);
}

function cleanupExpiredKeys() {
    const now = Date.now();
    for (const [sessionId, keyData] of temporaryKeys.entries()) {
        if (now > keyData.expires) {
            temporaryKeys.delete(sessionId);
        }
    }
}

function getUser(userId) {
    return users.find(user => user.id === userId);
}

function getSession(sessionId) {
    return activeSessions.get(sessionId);
}

function getAllUsers(req, res) {
    try {
        const userList = users.map(user => ({
            id: user.id,
            username: user.username,
            email: user.email,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
        }));

        res.json({
            success: true,
            users: userList
        });
    } catch (error) {
        console.error('❌ Get users error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve users'
        });
    }
}

ensureDataDirectory();
users = loadUsers();

router.post('/register', register);
router.post('/key-exchange', keyExchange);
router.post('/login', login);
router.post('/logout', logout);
router.get('/users', authenticateToken, getAllUsers);

module.exports = router;
module.exports.getUser = getUser;
module.exports.getSession = getSession;
module.exports.authenticateToken = authenticateToken;