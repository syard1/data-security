const express = require('express');
const { v4: uuidv4 } = require('uuid');

const cryptoService = require('../services/cryptoService');
const { getUser, authenticateToken } = require('./authController');

const router = express.Router();

const messages = new Map(); // In-memory message storage
const messageHistory = new Map(); // User message history

function getClientIp(req) {
    return req.headers['x-forwarded-for'] || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress || 
           req.ip || 
           'unknown';
}

async function encryptMessage(req, res) {
    try {
        const { message, recipientId } = req.body;
        const senderId = req.user.userId;
        const clientIp = getClientIp(req);

        if (!message || !recipientId) {
            return res.status(400).json({
                success: false,
                message: 'Message content and recipient ID required'
            });
        }

        const sender = getUser(senderId);
        if (!sender || !sender.aesSymmetricKey) {
            return res.status(400).json({
                success: false,
                message: 'Encryption key not found. Please log in again.',
                alert: {
                    type: 'ENCRYPT_ERROR',
                    description: 'AES symmetric key not found'
                }
            });
        }

        const recipient = getUser(recipientId);
        if (!recipient) {
            return res.status(404).json({
                success: false,
                message: 'Recipient not found'
            });
        }

        const messageObj = {
            id: uuidv4(),
            content: message,
            senderId: senderId,
            recipientId: recipientId,
            timestamp: new Date().toISOString(),
            clientIp: clientIp
        };

        const messageHash = cryptoService.sha256(JSON.stringify(messageObj));
        const isReplay = cryptoService.checkReplayAttack(messageHash, senderId);
        
        if (isReplay) {
            return res.status(400).json({
                success: false,
                message: 'Duplicate message detected',
                alert: {
                    type: 'REPLAY_ATTACK',
                    description: 'Message replay attack detected'
                }
            });
        }

        const encrypted = cryptoService.aesEncrypt(
            JSON.stringify(messageObj), 
            sender.aesSymmetricKey
        );

        const signature = cryptoService.signData(
            JSON.stringify(messageObj),
            cryptoService.getServerPrivateKey()
        );

        const encryptedMessage = {
            id: messageObj.id,
            encryptedContent: encrypted.encrypted,
            iv: encrypted.iv,
            signature: signature,
            senderId: senderId,
            recipientId: recipientId,
            timestamp: messageObj.timestamp,
            messageHash: messageHash
        };

        messages.set(messageObj.id, encryptedMessage);

        const senderHistory = messageHistory.get(senderId) || [];
        senderHistory.push({
            messageId: messageObj.id,
            recipientId: recipientId,
            timestamp: messageObj.timestamp,
            type: 'sent'
        });
        messageHistory.set(senderId, senderHistory);

        const recipientHistory = messageHistory.get(recipientId) || [];
        recipientHistory.push({
            messageId: messageObj.id,
            senderId: senderId,
            timestamp: messageObj.timestamp,
            type: 'received'
        });
        messageHistory.set(recipientId, recipientHistory);

        console.log(`📨 Message encrypted: ${senderId} → ${recipientId}`);

        res.json({
            success: true,
            messageId: messageObj.id,
            encryptedMessage: encrypted.encrypted,
            iv: encrypted.iv,
            signature: signature,
            timestamp: messageObj.timestamp
        });

    } catch (error) {
        console.error('❌ Message encryption error:', error);
        res.status(500).json({
            success: false,
            message: 'Message encryption failed'
        });
    }
}

async function decryptMessage(req, res) {
    try {
        const { messageId, encryptedContent, iv, signature } = req.body;
        const userId = req.user.userId;
        const clientIp = getClientIp(req);

        if (!messageId || !encryptedContent || !iv || !signature) {
            return res.status(400).json({
                success: false,
                message: 'Message ID, encrypted content, IV, and signature required'
            });
        }

        const user = getUser(userId);
        if (!user || !user.aesSymmetricKey) {
            return res.status(400).json({
                success: false,
                message: 'Decryption key not found. Please log in again.',
                alert: {
                    type: 'DECRYPT_ERROR',
                    description: 'AES symmetric key not found'
                }
            });
        }

        const storedMessage = messages.get(messageId);
        if (!storedMessage) {
            return res.status(404).json({
                success: false,
                message: 'Message not found'
            });
        }

        if (storedMessage.recipientId !== userId && storedMessage.senderId !== userId) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized to decrypt this message'
            });
        }

        let decryptedContent;
        try {
            decryptedContent = cryptoService.aesDecrypt(encryptedContent, user.aesSymmetricKey, iv);
        } catch (decryptError) {
            return res.status(400).json({
                success: false,
                message: 'Message decryption failed',
                alert: {
                    type: 'DECRYPT_ERROR',
                    description: 'Failed to decrypt message content'
                }
            });
        }

        let messageObj;
        try {
            messageObj = JSON.parse(decryptedContent);
        } catch (parseError) {
            return res.status(400).json({
                success: false,
                message: 'Invalid message format'
            });
        }

        const isValidSignature = cryptoService.verifySignature(
            decryptedContent,
            signature,
            cryptoService.getServerPublicKey()
        );

        if (!isValidSignature) {
            return res.status(400).json({
                success: false,
                message: 'Invalid message signature',
                alert: {
                    type: 'DECRYPT_ERROR',
                    description: 'Message signature verification failed'
                }
            });
        }

        console.log(`📖 Message decrypted: ${messageId} by ${userId}`);

        res.json({
            success: true,
            messageId: messageObj.id,
            content: messageObj.content,
            senderId: messageObj.senderId,
            recipientId: messageObj.recipientId,
            timestamp: messageObj.timestamp,
            signatureValid: true
        });

    } catch (error) {
        console.error('❌ Message decryption error:', error);
        res.status(500).json({
            success: false,
            message: 'Message decryption failed'
        });
    }
}

async function getMessageHistory(req, res) {
    try {
        const userId = req.user.userId;
        const { limit = 50, offset = 0 } = req.query;

        const userHistory = messageHistory.get(userId) || [];
        
        const sortedHistory = userHistory.sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );

        const paginatedHistory = sortedHistory.slice(
            parseInt(offset), 
            parseInt(offset) + parseInt(limit)
        );

        const enrichedHistory = paginatedHistory.map(historyItem => {
            const otherUserId = historyItem.type === 'sent' ? 
                historyItem.recipientId : historyItem.senderId;
            const otherUser = getUser(otherUserId);
            
            return {
                ...historyItem,
                otherUser: otherUser ? {
                    id: otherUser.id,
                    username: otherUser.username
                } : null
            };
        });

        res.json({
            success: true,
            messages: enrichedHistory,
            total: userHistory.length,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });

    } catch (error) {
        console.error('❌ Get message history error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve message history'
        });
    }
}

async function getMessage(req, res) {
    try {
        const { messageId } = req.params;
        const userId = req.user.userId;

        if (!messageId) {
            return res.status(400).json({
                success: false,
                message: 'Message ID required'
            });
        }

        const message = messages.get(messageId);
        if (!message) {
            return res.status(404).json({
                success: false,
                message: 'Message not found'
            });
        }

        if (message.recipientId !== userId && message.senderId !== userId) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized to access this message'
            });
        }

        res.json({
            success: true,
            message: message
        });

    } catch (error) {
        console.error('❌ Get message error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve message'
        });
    }
}

async function verifyMessage(encryptedMessage, signature, senderId) {
    try {
        const sender = getUser(senderId);
        if (!sender || !sender.aesSymmetricKey) {
            return false;
        }

        return cryptoService.verifySignature(
            encryptedMessage,
            signature,
            cryptoService.getServerPublicKey()
        );
    } catch (error) {
        console.error('❌ Message verification error:', error);
        return false;
    }
}

async function getMessageStats(req, res) {
    try {
        const userId = req.user.userId;
        const userHistory = messageHistory.get(userId) || [];

        const stats = {
            totalMessages: userHistory.length,
            sentMessages: userHistory.filter(m => m.type === 'sent').length,
            receivedMessages: userHistory.filter(m => m.type === 'received').length,
            uniqueContacts: new Set([
                ...userHistory.filter(m => m.type === 'sent').map(m => m.recipientId),
                ...userHistory.filter(m => m.type === 'received').map(m => m.senderId)
            ]).size
        };

        res.json({
            success: true,
            stats
        });

    } catch (error) {
        console.error('❌ Get message stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve message statistics'
        });
    }
}

async function clearMessages(req, res) {
    try {
        const userId = req.user.userId;
        
        messageHistory.delete(userId);
        
        for (const [messageId, message] of messages.entries()) {
            if (message.senderId === userId || message.recipientId === userId) {
                messages.delete(messageId);
            }
        }

        console.log(`🗑️ Messages cleared for user: ${userId}`);

        res.json({
            success: true,
            message: 'Messages cleared successfully'
        });

    } catch (error) {
        console.error('❌ Clear messages error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to clear messages'
        });
    }
}

router.post('/encrypt', authenticateToken, encryptMessage);
router.post('/decrypt', authenticateToken, decryptMessage);
router.get('/history', authenticateToken, getMessageHistory);
router.get('/stats', authenticateToken, getMessageStats);
router.get('/:messageId', authenticateToken, getMessage);
router.delete('/clear', authenticateToken, clearMessages);

module.exports = router;
module.exports.verifyMessage = verifyMessage;