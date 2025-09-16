const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class CryptoService {
    constructor() {
        this.serverKeyPair = null;
        this.sessionKeys = new Map();
        this.certificates = new Map();
        this.messageHashes = new Map(); // For replay attack detection
    }

    initialize() {
        this.ensureCertsDirectory();
        this.initializeServerKeys();
        console.log('🔐 Crypto service initialized');
    }

    ensureCertsDirectory() {
        const certsDir = path.join(__dirname, '../certs');
        if (!fs.existsSync(certsDir)) {
            fs.mkdirSync(certsDir, { recursive: true });
        }
    }

    initializeServerKeys() {
        const keyPath = path.join(__dirname, '../certs/server-key.pem');
        const certPath = path.join(__dirname, '../certs/server-cert.pem');
        
        if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
            this.generateServerCertificate();
        } else {
            this.loadServerKeys();
        }
    }

    generateServerCertificate() {
        console.log('🔑 Generating new server certificate...');
        
        const keyPair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        this.serverKeyPair = keyPair;
        
        const cert = this.createSelfSignedCert(keyPair.publicKey);
        
        const certsDir = path.join(__dirname, '../certs');
        fs.writeFileSync(path.join(certsDir, 'server-key.pem'), keyPair.privateKey);
        fs.writeFileSync(path.join(certsDir, 'server-cert.pem'), cert);
        fs.writeFileSync(path.join(certsDir, 'server-public.pem'), keyPair.publicKey);
        
        console.log('✅ Server certificate generated successfully');
    }

    loadServerKeys() {
        try {
            const certsDir = path.join(__dirname, '../certs');
            const privateKey = fs.readFileSync(path.join(certsDir, 'server-key.pem'), 'utf8');
            const publicKey = fs.readFileSync(path.join(certsDir, 'server-public.pem'), 'utf8');
            
            this.serverKeyPair = { privateKey, publicKey };
            console.log('✅ Server keys loaded successfully');
        } catch (error) {
            console.error('❌ Error loading server keys:', error);
            this.generateServerCertificate();
        }
    }

    createSelfSignedCert(publicKey) {
        const certInfo = {
            commonName: 'SecureMessaging-Server',
            organization: 'Secure Messaging Inc',
            country: 'AL',
            validFrom: new Date(),
            validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
        };

        const certData = {
            version: 3,
            serialNumber: this.generateRandomBytes(16).toString('hex'),
            issuer: certInfo,
            subject: certInfo,
            publicKey: publicKey,
            validFrom: certInfo.validFrom.toISOString(),
            validTo: certInfo.validTo.toISOString(),
            extensions: {
                keyUsage: ['digitalSignature', 'keyEncipherment'],
                extKeyUsage: ['serverAuth'],
                subjectAltName: ['DNS:localhost', 'IP:127.0.0.1']
            }
        };

        certData.signature = this.signData(JSON.stringify(certData), this.serverKeyPair.privateKey);

        return JSON.stringify(certData, null, 2);
    }

    rsaEncrypt(data, publicKey) {
        try {
            const encrypted = crypto.publicEncrypt(
                {
                    key: publicKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: 'sha256'
                },
                Buffer.from(data, 'utf8')
            );
            return encrypted.toString('base64');
        } catch (error) {
            throw new Error(`RSA encryption failed: ${error.message}`);
        }
    }

    rsaDecrypt(encryptedData, privateKey) {
        try {
            const decrypted = crypto.privateDecrypt(
                {
                    key: privateKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: 'sha256'
                },
                Buffer.from(encryptedData, 'base64')
            );
            return decrypted.toString('utf8');
        } catch (error) {
            throw new Error(`RSA decryption failed: ${error.message}`);
        }
    }

    aesEncrypt(data, key) {
        try {
            const iv = crypto.randomBytes(16);
            const keyBuffer = crypto.createHash('sha256').update(key, 'utf8').digest();
            const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, iv);
            
            let encrypted = cipher.update(data, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            return { 
                encrypted, 
                iv: iv.toString('hex'),
                algorithm: 'aes-256-cbc'
            };
        } catch (error) {
            throw new Error(`AES encryption failed: ${error.message}`);
        }
    }

    aesDecrypt(encryptedData, key, iv) {
        try {
            const keyBuffer = crypto.createHash('sha256').update(key, 'utf8').digest();
            const ivBuffer = Buffer.from(iv, 'hex');

            const attempts = [
                { name: 'base64', encoding: 'base64' },
                { name: 'hex', encoding: 'hex' },
                { name: 'base64-cryptojs-format', encoding: 'base64', preprocess: true }
            ];

            for (const attempt of attempts) {
                try {
                    let dataToDecrypt = encryptedData;
                    
                    if (attempt.preprocess) {
                        if (encryptedData.startsWith('U2FsdGVk')) { // "Salted__" in base64
                            const decoded = Buffer.from(encryptedData, 'base64');
                            if (decoded.length > 16) {
                                dataToDecrypt = decoded.slice(16).toString('base64');
                            }
                        }
                    }
                    
                    const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, ivBuffer);
                    let decrypted = decipher.update(dataToDecrypt, attempt.encoding, 'utf8');
                    decrypted += decipher.final('utf8');
                    
                    return decrypted;
                } catch (attemptError) {
                    continue;
                }
            }
            
            throw new Error('All decryption attempts failed');
        } catch (error) {
            throw new Error(`AES decryption failed: ${error.message}`);
        }
    }

    signData(data, privateKey) {
        try {
            const sign = crypto.createSign('RSA-SHA256');
            sign.update(data, 'utf8');
            return sign.sign(privateKey, 'hex');
        } catch (error) {
            throw new Error(`Signing failed: ${error.message}`);
        }
    }

    verifySignature(data, signature, publicKey) {
        try {
            const verify = crypto.createVerify('RSA-SHA256');
            verify.update(data, 'utf8');
            return verify.verify(publicKey, signature, 'hex');
        } catch (error) {
            console.error('Signature verification error:', error);
            return false;
        }
    }

    generateECDHKeyPair() {
        return crypto.generateKeyPairSync('ec', {
            namedCurve: 'secp256k1',
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
    }

    deriveSharedSecret(privateKey, publicKey) {
        try {
            const ecdh = crypto.createECDH('secp256k1');
            ecdh.setPrivateKey(privateKey, 'pem');
            return ecdh.computeSecret(publicKey, 'pem', 'hex');
        } catch (error) {
            throw new Error(`ECDH key derivation failed: ${error.message}`);
        }
    }

    generateSessionKey(sessionId) {
        const key = crypto.randomBytes(32).toString('hex');
        this.sessionKeys.set(sessionId, {
            key,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
        });
        return key;
    }

    getSessionKey(sessionId) {
        const sessionData = this.sessionKeys.get(sessionId);
        if (!sessionData) return null;
        
        if (new Date() > sessionData.expiresAt) {
            this.sessionKeys.delete(sessionId);
            return null;
        }
        
        return sessionData.key;
    }

    removeSessionKey(sessionId) {
        return this.sessionKeys.delete(sessionId);
    }

    generateRandomBytes(length) {
        return crypto.randomBytes(length);
    }

    generateRandomHex(length) {
        return crypto.randomBytes(length).toString('hex');
    }

    sha256(data) {
        return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
    }

    verifyCertificate(cert) {
        try {
            const certObj = JSON.parse(cert);
            const now = new Date();
            const validFrom = new Date(certObj.validFrom);
            const validTo = new Date(certObj.validTo);
            
            if (now < validFrom || now > validTo) {
                return { 
                    valid: false, 
                    reason: 'Certificate expired or not yet valid',
                    details: { validFrom, validTo, now }
                };
            }

            const certDataForSigning = JSON.stringify({
                version: certObj.version,
                serialNumber: certObj.serialNumber,
                issuer: certObj.issuer,
                subject: certObj.subject,
                publicKey: certObj.publicKey,
                validFrom: certObj.validFrom,
                validTo: certObj.validTo,
                extensions: certObj.extensions
            });

            const signatureValid = this.verifySignature(
                certDataForSigning, 
                certObj.signature, 
                this.getServerPublicKey()
            );
            
            return { 
                valid: signatureValid, 
                reason: signatureValid ? 'Valid certificate' : 'Invalid signature',
                details: certObj
            };
        } catch (error) {
            return { 
                valid: false, 
                reason: 'Invalid certificate format',
                error: error.message
            };
        }
    }

    checkReplayAttack(messageHash, sessionId) {
        const sessionHashes = this.messageHashes.get(sessionId) || new Set();
        
        if (sessionHashes.has(messageHash)) {
            return true; // Replay detected
        }
        
        sessionHashes.add(messageHash);
        
        if (sessionHashes.size > 1000) {
            const hashArray = Array.from(sessionHashes);
            sessionHashes.clear();
            hashArray.slice(-500).forEach(hash => sessionHashes.add(hash));
        }
        
        this.messageHashes.set(sessionId, sessionHashes);
        return false; // No replay detected
    }

    getServerCertificate() {
        const certPath = path.join(__dirname, '../certs/server-cert.pem');
        if (fs.existsSync(certPath)) {
            return fs.readFileSync(certPath, 'utf8');
        }
        return null;
    }

    getServerPublicKey() {
        return this.serverKeyPair?.publicKey || null;
    }

    getServerPrivateKey() {
        return this.serverKeyPair?.privateKey || null;
    }

    cleanupExpiredSessions() {
        const now = new Date();
        for (const [sessionId, sessionData] of this.sessionKeys.entries()) {
            if (now > sessionData.expiresAt) {
                this.sessionKeys.delete(sessionId);
                this.messageHashes.delete(sessionId);
            }
        }
    }
}

module.exports = new CryptoService();
