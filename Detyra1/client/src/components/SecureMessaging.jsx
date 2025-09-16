import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useCrypto } from '../context/CryptoContext';
import { 
  PaperAirplaneIcon,
  LockClosedIcon,
  UserIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  EyeIcon,
  DocumentTextIcon,
  ArrowRightOnRectangleIcon,
  CogIcon
} from '@heroicons/react/24/outline';

const SecureMessaging = () => {
  const { user, logout } = useAuth();
  const { tlsHandshakeStatus, encryptMessage, decryptMessage } = useCrypto();
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState([]);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [messagePreview, setMessagePreview] = useState(null);

  const recipient = { id: 'server', username: 'Server', type: 'system' };

  const handlePreviewMessage = async () => {
    if (!message.trim()) return;
    
    if (!tlsHandshakeStatus.completed) {
      alert('Please complete TLS handshake first!');
      return;
    }

    try {
      const result = await encryptMessage(message);
      
      if (result.success) {
        setMessagePreview({
          originalMessage: message,
          encryptedContent: result.encryptedMessage,
          iv: result.iv,
          signature: result.signature,
          sender: user.username,
          recipient: recipient.username,
          timestamp: new Date().toISOString(),
          encryptionAlgorithm: 'AES-256-CBC',
          signatureAlgorithm: 'RSA-2048'
        });
        setShowPreview(true);
      } else {
        alert(`Encryption failed: ${result.message}`);
      }
    } catch (error) {
      alert(`Error: ${error.message}`);
    }
  };

  const handleSendMessage = async () => {
    if (messagePreview) {
      const newMessage = {
        id: Date.now(),
        content: messagePreview.originalMessage,
        encryptedContent: messagePreview.encryptedContent,
        iv: messagePreview.iv,
        signature: messagePreview.signature,
        sender: messagePreview.sender,
        recipient: messagePreview.recipient,
        timestamp: messagePreview.timestamp,
        type: 'sent'
      };
      
      setMessages(prev => [...prev, newMessage]);
      setMessage('');
      setShowPreview(false);
      setMessagePreview(null);
      
      setTimeout(() => {
        const response = {
          id: Date.now() + 1,
          content: `Message received and verified: "${messagePreview.originalMessage}"`,
          sender: 'Server',
          recipient: user.username,
          timestamp: new Date().toISOString(),
          type: 'received',
          encrypted: true
        };
        setMessages(prev => [...prev, response]);
      }, 1000);
    } else {
      handlePreviewMessage();
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  return (
    <div className="min-h-screen gradient-bg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <nav className="glass-dark border-b border-gray-700 backdrop-blur-xl mb-8">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center h-16">
              <div className="flex items-center">
                <div className="h-10 w-10 flex items-center justify-center rounded-xl bg-gradient-to-r from-primary-500 to-primary-600 shadow-glow mr-4">
                  <ShieldCheckIcon className="h-6 w-6 text-white" />
                </div>
                <div>
                  <h1 className="text-xl font-bold text-white">SecureChat</h1>
                  <p className="text-xs text-gray-400">Secure Messaging</p>
                </div>
              </div>
              <div className="flex items-center space-x-4">
                <span className="text-gray-300">Welcome, {user?.username}</span>
                <Link
                  to="/tls"
                  className="px-3 py-2 rounded-md text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 transition-colors"
                >
                  <CogIcon className="h-4 w-4 inline mr-2" />
                  TLS Settings
                </Link>
                <button
                  onClick={logout}
                  className="px-3 py-2 rounded-md text-sm font-medium bg-red-600 text-white hover:bg-red-700 transition-colors"
                >
                  <ArrowRightOnRectangleIcon className="h-4 w-4 inline mr-2" />
                  Logout
                </button>
              </div>
            </div>
          </div>
        </nav>

        <div className="mb-8 animate-slideInDown">
          <div className="text-center lg:text-left">
            <h2 className="text-4xl font-bold text-white mb-4">
              <span className="bg-gradient-to-r from-success-300 to-primary-500 bg-clip-text text-transparent">
                Secure Messaging
              </span>
            </h2>
            <p className="text-lg text-gray-300 max-w-2xl">
              Send end-to-end encrypted messages with AES-256 encryption and RSA digital signatures
            </p>
            <div className="mt-4 flex items-center justify-center lg:justify-start space-x-6 text-sm text-gray-400">
              <div className="flex items-center">
                <div className="h-2 w-2 bg-success-500 rounded-full mr-2 animate-pulse"></div>
                {tlsHandshakeStatus.completed ? 'Secure Channel Active' : 'Awaiting TLS Handshake'}
              </div>
              <div className="flex items-center">
                <div className="h-2 w-2 bg-primary-500 rounded-full mr-2"></div>
                Message Integrity Protection
              </div>
              <div className="flex items-center">
                <div className="h-2 w-2 bg-warning-500 rounded-full mr-2"></div>
                Perfect Forward Secrecy
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          <div className="lg:col-span-1">
            <div className="security-card">
              <h2 className="text-lg font-bold text-white mb-4">Recipient</h2>
              <div className="space-y-2">
                <div className="w-full p-3 rounded-lg bg-blue-600 text-white">
                  <div className="flex items-center">
                    <UserIcon className="h-5 w-5 mr-3" />
                    <div>
                      <p className="font-medium">{recipient.username}</p>
                      <p className="text-xs opacity-75">
                        {recipient.type === 'system' ? 'System' : 'User'}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="lg:col-span-3">
            <div className="security-card h-96 flex flex-col">
              <div className="flex-1 p-4 overflow-y-auto custom-scrollbar">
                <div className="space-y-4">
                  {messages.length === 0 ? (
                    <div className="text-center py-8">
                      <LockClosedIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                      <p className="text-gray-400">No messages yet. Start a secure conversation!</p>
                    </div>
                  ) : (
                    messages.map((msg) => (
                      <div
                        key={msg.id}
                        className={`flex ${msg.type === 'sent' ? 'justify-end' : 'justify-start'}`}
                      >
                        <div
                          className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
                            msg.type === 'sent'
                              ? 'message-sent'
                              : 'message-received'
                          }`}
                        >
                          <div className="flex items-center mb-1">
                            <span className="text-xs font-medium">
                              {msg.sender}
                            </span>
                            {(msg.encrypted || msg.encryptedContent) && (
                              <LockClosedIcon className="h-3 w-3 ml-2 text-green-400" />
                            )}
                          </div>
                          <p className="text-sm">{msg.content}</p>
                          <p className="text-xs opacity-75 mt-1">
                            {new Date(msg.timestamp).toLocaleTimeString()}
                          </p>
                          {msg.signature && (
                            <div className="mt-2 p-2 bg-black bg-opacity-30 rounded text-xs">
                              <p className="text-green-400 mb-1">✓ Digitally Signed</p>
                              <p className="font-mono break-all">
                                {msg.signature.substring(0, 32)}...
                              </p>
                            </div>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="border-t border-gray-600 p-4">
                <div className="flex space-x-2">
                  <input
                    type="text"
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    onKeyPress={handleKeyPress}
                    placeholder={
                      tlsHandshakeStatus.completed 
                        ? "Type your secure message..." 
                        : "Complete TLS handshake to send messages"
                    }
                    disabled={!tlsHandshakeStatus.completed || isEncrypting}
                    className="flex-1 px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                  />
                  <button
                    onClick={handlePreviewMessage}
                    disabled={!message.trim() || !tlsHandshakeStatus.completed || isEncrypting}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg transition-colors duration-200 flex items-center"
                  >
                    <EyeIcon className="h-4 w-4 mr-2" />
                    Preview
                  </button>
                  <button
                    onClick={handleSendMessage}
                    disabled={!message.trim() || !tlsHandshakeStatus.completed || isEncrypting}
                    className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg transition-colors duration-200 flex items-center"
                  >
                    <PaperAirplaneIcon className="h-4 w-4 mr-2" />
                    Send
                  </button>
                </div>
              </div>
            </div>

            <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="security-card">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <PaperAirplaneIcon className="h-8 w-8 text-blue-400" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-400">Messages Sent</p>
                    <p className="text-2xl font-bold text-white">
                      {messages.filter(m => m.type === 'sent').length}
                    </p>
                  </div>
                </div>
              </div>

              <div className="security-card">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <LockClosedIcon className="h-8 w-8 text-green-400" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-400">Encrypted</p>
                    <p className="text-2xl font-bold text-white">
                      {messages.filter(m => m.encryptedContent || m.encrypted).length}
                    </p>
                  </div>
                </div>
              </div>

              <div className="security-card">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <ShieldCheckIcon className="h-8 w-8 text-purple-400" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-400">Signed</p>
                    <p className="text-2xl font-bold text-white">
                      {messages.filter(m => m.signature).length}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {showPreview && messagePreview && (
          <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50">
            <div className="bg-gray-800 rounded-lg p-6 max-w-4xl w-full mx-4 max-h-96 overflow-y-auto">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xl font-bold text-white flex items-center">
                  <DocumentTextIcon className="h-6 w-6 mr-2" />
                  Message Preview
                </h3>
                <button
                  onClick={() => setShowPreview(false)}
                  className="text-gray-400 hover:text-white"
                >
                  ✕
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="security-card">
                  <h3 className="text-sm font-medium text-gray-300 mb-2">Message Details</h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">From:</span>
                      <span className="text-white">{messagePreview.sender}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">To:</span>
                      <span className="text-white">{messagePreview.recipient}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Timestamp:</span>
                      <span className="text-white">{new Date(messagePreview.timestamp).toLocaleString()}</span>
                    </div>
                  </div>
                </div>

                <div className="security-card">
                  <h3 className="text-sm font-medium text-gray-300 mb-2">Encryption Details</h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Encryption:</span>
                      <span className="text-green-400">{messagePreview.encryptionAlgorithm}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Signature:</span>
                      <span className="text-blue-400">{messagePreview.signatureAlgorithm}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">IV Length:</span>
                      <span className="text-white">{messagePreview.iv?.length || 0} chars</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="security-card mt-4">
                <h3 className="text-sm font-medium text-gray-300 mb-3">Encrypted Content</h3>
                <div className="bg-gray-900 rounded-lg p-4">
                  <p className="text-green-400 text-xs font-mono break-all">{messagePreview.encryptedContent}</p>
                </div>
              </div>

              <div className="flex justify-end space-x-4 pt-4 border-t border-gray-700">
                <button
                  onClick={() => {
                    setShowPreview(false);
                    setMessagePreview(null);
                  }}
                  className="px-6 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg font-medium transition-colors duration-200"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSendMessage}
                  className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors duration-200 flex items-center"
                >
                  <PaperAirplaneIcon className="h-4 w-4 mr-2" />
                  Send Message
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SecureMessaging;