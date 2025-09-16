const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');

const authController = require('./controllers/authController');
const tlsController = require('./controllers/tlsController');
const messageController = require('./controllers/messageController');
const alertController = require('./controllers/alertController');
const cryptoService = require('./services/cryptoService');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: ["http://localhost:3000", "http://localhost:3001", "http://localhost:5173", "http://localhost:5174", "http://localhost:5175"],
        methods: ["GET", "POST"],
        credentials: true
    }
});

const PORT = process.env.PORT || 5001;

app.use(helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: false
}));

app.use(cors({
    origin: ["http://localhost:3000", "http://localhost:3001", "http://localhost:5173", "http://localhost:5174", "http://localhost:5175"],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));

cryptoService.initialize();

app.use('/api/auth', authController);
app.use('/api/tls', tlsController);
app.use('/api/messages', messageController);
app.use('/api/alerts', alertController);

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        server: 'Secure Messaging Server'
    });
});

io.on('connection', (socket) => {
    
    socket.on('join-room', (data) => {
        const { userId, sessionId } = data;
        socket.join(`user-${userId}`);
        console.log(`👤 User ${userId} joined room with session ${sessionId}`);
    });
    
    socket.on('secure-message', async (data) => {
        try {
            const { encryptedMessage, signature, recipientId, senderId, sessionId } = data;
            
            const isValid = await messageController.verifyMessage(encryptedMessage, signature, senderId);
            
            if (!isValid) {
                socket.emit('message-error', { error: 'Invalid message signature' });
                return;
            }
            
            io.to(`user-${recipientId}`).emit('new-message', {
                encryptedMessage,
                signature,
                senderId,
                timestamp: new Date().toISOString()
            });
            
            console.log(`Secure message forwarded from ${senderId} to ${recipientId}`);
            
        } catch (error) {
            console.error('Socket message error:', error);
        }
    });
    
    socket.on('disconnect', () => {
        console.log(`🔌 Client disconnected: ${socket.id}`);
    });
});

app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ 
        success: false, 
        message: 'Internal server error'
    });
});

app.use('*', (req, res) => {
    res.status(404).json({ 
        success: false, 
        message: 'Endpoint not found' 
    });
});

server.listen(PORT, () => {
    console.log(`Secure Messaging Server running on port ${PORT}`);
    console.log(`TLS-like protocol enabled`);
    console.log(`WebSocket support enabled`);
    console.log(`Alerts are now handled client-side`);
});

module.exports = { app, server, io };