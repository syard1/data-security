const express = require('express');
const { v4: uuidv4 } = require('uuid');

const cryptoService = require('../services/cryptoService');

const router = express.Router();

const handshakeSessions = new Map();
const supportedVersions = ['TLS1.2', 'TLS1.3'];
const supportedCipherSuites = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
];

setInterval(() => cleanupExpiredHandshakes(), 10 * 60 * 1000);

function getClientIp(req) {
    return req.headers['x-forwarded-for'] || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress || 
           req.ip || 
           'unknown';
}

function validateTLSVersion(version) {
    if (!supportedVersions.includes(version)) {
        return {
            type: 'PROTOCOL_VERSION',
            description: 'Unsupported TLS version detected'
        };
    }
    
    if (version === 'TLS1.0' || version === 'TLS1.1') {
        return {
            type: 'DOWNGRADE_ATTACK',
            description: 'Weak TLS version detected'
        };
    }
    
    return null;
}

function validateCipherSuite(cipher) {
    const weakCiphers = ['RC4', 'DES', 'MD5', 'SHA1'];
    
    if (weakCiphers.some(weak => cipher.includes(weak))) {
        return {
            type: 'INSUFFICIENT_SECURITY',
            description: 'Weak cipher suite detected'
        };
    }
    
    return null;
}

async function clientHello(req, res) {
    try {
        const { clientHello } = req.body;
        const clientIp = getClientIp(req);

        if (!clientHello) {
            return res.status(400).json({
                success: false,
                message: 'Client Hello required'
            });
        }

        const versionAlert = validateTLSVersion(clientHello.version);
        if (versionAlert) {
            return res.status(400).json({
                success: false,
                alert: versionAlert,
                message: 'Unsupported TLS version'
            });
        }

        const clientCiphers = clientHello.cipherSuites || [];
        const supportedCipher = clientCiphers.find(cipher => 
            supportedCipherSuites.includes(cipher)
        );

        if (!supportedCipher) {
            const alert = {
                type: 'INSUFFICIENT_SECURITY',
                description: 'No supported cipher suites found'
            };
            return res.status(400).json({
                success: false,
                alert: alert,
                message: 'No supported cipher suites'
            });
        }

        const cipherAlert = validateCipherSuite(supportedCipher);
        if (cipherAlert) {
            return res.status(400).json({
                success: false,
                alert: cipherAlert,
                message: 'Weak cipher suite detected'
            });
        }

        const sessionId = uuidv4();
        const serverRandom = cryptoService.generateRandomHex(32);
        
        const handshakeSession = {
            sessionId,
            clientIp,
            version: clientHello.version,
            selectedCipher: supportedCipher,
            clientRandom: clientHello.clientRandom,
            serverRandom,
            timestamp: new Date(),
            stage: 'CLIENT_HELLO_RECEIVED'
        };

        handshakeSessions.set(sessionId, handshakeSession);

        console.log(`🤝 TLS Handshake initiated - Session: ${sessionId} - Client: ${clientIp}`);

        const serverHello = {
            success: true,
            sessionId,
            version: clientHello.version,
            selectedCipher: supportedCipher,
            serverRandom,
            compressionMethod: 'null',
            extensions: {
                serverName: 'SecureMessaging-Server',
                supportedVersions: supportedVersions,
                keyShare: null // Will be populated in key exchange
            }
        };

        res.json(serverHello);

    } catch (error) {
        console.error('❌ Client Hello error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Handshake failed' 
        });
    }
}

async function certificateExchange(req, res) {
    try {
        const { sessionId } = req.body;
        const clientIp = getClientIp(req);

        if (!sessionId) {
            return res.status(400).json({
                success: false,
                message: 'Session ID required'
            });
        }

        const handshakeSession = handshakeSessions.get(sessionId);
        if (!handshakeSession) {
            return res.status(400).json({
                success: false,
                message: 'Invalid handshake session'
            });
        }

        const serverCertificate = cryptoService.getServerCertificate();
        if (!serverCertificate) {
            return res.status(500).json({
                success: false,
                message: 'Server certificate error'
            });
        }

        handshakeSession.stage = 'CERTIFICATE_SENT';
        handshakeSession.serverCertificate = serverCertificate;

        console.log(`📜 Certificate sent - Session: ${sessionId}`);


        console.log("certificate exchange", serverCertificate);
        res.json({
            success: true,
            certificate: serverCertificate
        });

    } catch (error) {
        console.error('❌ Certificate exchange error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Certificate exchange failed' 
        });
    }
}

async function keyExchange(req, res) {
    try {
        const { sessionId, keyExchangeMethod, clientKeyShare } = req.body;
        const clientIp = getClientIp(req);

        if (!sessionId || !keyExchangeMethod) {
            return res.status(400).json({
                success: false,
                message: 'Session ID and key exchange method required'
            });
        }

        const handshakeSession = handshakeSessions.get(sessionId);
        if (!handshakeSession) {
            return res.status(400).json({
                success: false,
                message: 'Invalid handshake session'
            });
        }

        let sharedSecret;
        let serverKeyShare;

        if (keyExchangeMethod === 'RSA') {
            if (!clientKeyShare) {
                return res.status(400).json({
                    success: false,
                    message: 'Client key share required for RSA'
                });
            }

            try {
                const preMasterSecret = cryptoService.rsaDecrypt(
                    clientKeyShare, 
                    cryptoService.getServerPrivateKey()
                );
                sharedSecret = cryptoService.sha256(preMasterSecret + handshakeSession.clientRandom + handshakeSession.serverRandom);
            } catch (error) {
                return res.status(400).json({
                    success: false,
                    message: 'RSA key exchange failed'
                });
            }

        } else if (keyExchangeMethod === 'ECDHE') {
            const serverECDHKeyPair = cryptoService.generateECDHKeyPair();
            serverKeyShare = serverECDHKeyPair.publicKey;

            if (clientKeyShare) {
                try {
                    sharedSecret = cryptoService.deriveSharedSecret(
                        serverECDHKeyPair.privateKey,
                        clientKeyShare
                    );
                } catch (error) {
                    return res.status(400).json({
                        success: false,
                        message: 'ECDHE key exchange failed'
                    });
                }
            } else {
                handshakeSession.stage = 'SERVER_KEY_SHARE_SENT';
                handshakeSession.serverECDHPrivateKey = serverECDHKeyPair.privateKey;

                return res.json({
                    success: true,
                    serverKeyShare: serverKeyShare,
                    waitingForClientKeyShare: true
                });
            }

        } else {
            return res.status(400).json({
                success: false,
                message: 'Unsupported key exchange method'
            });
        }

        const masterSecret = cryptoService.sha256(sharedSecret + 'master secret' + handshakeSession.clientRandom + handshakeSession.serverRandom);
        const sessionKey = cryptoService.sha256(masterSecret + 'session key').substring(0, 64); // 32 bytes hex

        cryptoService.generateSessionKey(sessionId); // This will be replaced with our derived key
        handshakeSession.masterSecret = masterSecret;
        handshakeSession.sessionKey = sessionKey;
        handshakeSession.stage = 'KEY_EXCHANGE_COMPLETE';

        console.log(`🔑 Key exchange complete - Session: ${sessionId} - Method: ${keyExchangeMethod}`);

        res.json({
            success: true,
            keyExchangeComplete: true,
            serverKeyShare: serverKeyShare,
            sessionEstablished: true
        });

    } catch (error) {
        console.error('❌ Key exchange error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Key exchange failed' 
        });
    }
}

async function handshakeFinished(req, res) {
    try {
        const { sessionId, clientFinished } = req.body;
        const clientIp = getClientIp(req);

        if (!sessionId) {
            return res.status(400).json({
                success: false,
                message: 'Session ID required'
            });
        }

        const handshakeSession = handshakeSessions.get(sessionId);
        if (!handshakeSession) {
            return res.status(400).json({
                success: false,
                message: 'Invalid handshake session'
            });
        }

        if (handshakeSession.stage !== 'KEY_EXCHANGE_COMPLETE') {
            return res.status(400).json({
                success: false,
                message: 'Key exchange not complete'
            });
        }

        if (clientFinished) {
            const expectedFinished = cryptoService.sha256(handshakeSession.masterSecret + 'client finished');
            if (clientFinished !== expectedFinished) {
                return res.status(400).json({
                    success: false,
                    message: 'Handshake verification failed'
                });
            }
        }

        const serverFinished = cryptoService.sha256(handshakeSession.masterSecret + 'server finished');

        handshakeSession.stage = 'HANDSHAKE_COMPLETE';
        handshakeSession.completedAt = new Date();

        cryptoService.sessionKeys.set(sessionId, {
            key: handshakeSession.sessionKey,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
        });

        console.log(`✅ TLS Handshake completed - Session: ${sessionId} - Client: ${clientIp}`);

        res.json({
            success: true,
            handshakeComplete: true,
            serverFinished: serverFinished,
            sessionKey: handshakeSession.sessionKey,
            message: 'Secure channel established'
        });

    } catch (error) {
        console.error('❌ Handshake finish error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Handshake finish failed' 
        });
    }
}

function getHandshakeStatus(req, res) {
    try {
        const { sessionId } = req.params;

        if (!sessionId) {
            return res.status(400).json({
                success: false,
                message: 'Session ID required'
            });
        }

        const handshakeSession = handshakeSessions.get(sessionId);
        if (!handshakeSession) {
            return res.status(404).json({
                success: false,
                message: 'Handshake session not found'
            });
        }

        res.json({
            success: true,
            sessionId: handshakeSession.sessionId,
            stage: handshakeSession.stage,
            version: handshakeSession.version,
            selectedCipher: handshakeSession.selectedCipher,
            timestamp: handshakeSession.timestamp,
            completedAt: handshakeSession.completedAt
        });

    } catch (error) {
        console.error('❌ Get handshake status error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get handshake status'
        });
    }
}

function simulateDowngradeAttack(req, res) {
    try {
        const { originalVersion, attackVersion, cipherSuites } = req.body;
        const clientIp = getClientIp(req);

        const isVersionDowngrade = originalVersion === 'TLS1.3' && attackVersion !== 'TLS1.3';
        const hasWeakCiphers = cipherSuites && cipherSuites.some(cipher => 
            cipher.includes('RC4') || cipher.includes('DES') || cipher.includes('MD5')
        );

        if (isVersionDowngrade || hasWeakCiphers) {
            const alert = {
                type: 'DOWNGRADE_ATTACK',
                description: 'TLS downgrade attack detected and blocked',
                context: {
                    clientIp,
                    originalVersion,
                    attackVersion,
                    cipherSuites,
                    reason: isVersionDowngrade ? 'Version downgrade' : 'Weak cipher suites'
                }
            };

            return res.json({
                success: false,
                blocked: true,
                alert: alert,
                reason: 'Downgrade attack detected and blocked'
            });
        }

        res.json({
            success: true,
            blocked: false,
            message: 'No downgrade attack detected'
        });

    } catch (error) {
        console.error('❌ Downgrade attack simulation error:', error);
        res.status(500).json({
            success: false,
            message: 'Simulation failed'
        });
    }
}

function cleanupExpiredHandshakes() {
    const now = new Date();
    const expirationTime = 10 * 60 * 1000; // 10 minutes

    for (const [sessionId, session] of handshakeSessions.entries()) {
        if (now - session.timestamp > expirationTime) {
            handshakeSessions.delete(sessionId);
        }
    }

    console.log(`🧹 Cleaned up expired handshake sessions. Active: ${handshakeSessions.size}`);
}

function getSupportedConfigurations(req, res) {
    res.json({
        success: true,
        supportedVersions: supportedVersions,
        supportedCipherSuites: supportedCipherSuites,
        keyExchangeMethods: ['RSA', 'ECDHE'],
        serverCertificate: cryptoService.getServerCertificate()
    });
}

router.post('/handshake/client-hello', clientHello);
router.post('/handshake/certificate', certificateExchange);
function getHandshakeSession(sessionId) {
    return handshakeSessions.get(sessionId);
}

router.post('/handshake/key-exchange', keyExchange);
router.post('/handshake/finished', handshakeFinished);
router.get('/handshake/status/:sessionId', getHandshakeStatus);
router.post('/demo/downgrade-attack', simulateDowngradeAttack);
router.get('/supported', getSupportedConfigurations);

module.exports = router;
module.exports.getHandshakeSession = getHandshakeSession;