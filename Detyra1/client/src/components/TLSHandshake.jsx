import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useCrypto } from '../context/CryptoContext';
import { useAlert } from '../context/AlertContext';
import { useAuth } from '../context/AuthContext';
import { 
  ShieldCheckIcon, 
  KeyIcon, 
  DocumentTextIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
  ChatBubbleLeftRightIcon,
  ArrowRightOnRectangleIcon
} from '@heroicons/react/24/outline';

const TLSHandshake = () => {
  const { 
    tlsHandshakeStatus, 
    performTLSHandshake, 
    resetHandshake, 
    keyPair,
    serverCertificate,
    sessionKey
  } = useCrypto();
  
  const { simulateAttack } = useAlert();
  const { user, logout } = useAuth();
  
  const [isPerformingHandshake, setIsPerformingHandshake] = useState(false);
  const [handshakeLog, setHandshakeLog] = useState([]);
  const [showCertificateDetails, setShowCertificateDetails] = useState(false);

  const handshakeSteps = [
    {
      id: 'client_hello',
      title: 'Client Hello',
      description: 'Send supported TLS versions and cipher suites',
      stage: 'STARTING'
    },
    {
      id: 'server_hello',
      title: 'Server Hello',
      description: 'Receive server response with selected parameters',
      stage: 'SERVER_HELLO_RECEIVED'
    },
    {
      id: 'certificate',
      title: 'Certificate Exchange',
      description: 'Verify server certificate and public key',
      stage: 'CERTIFICATE_RECEIVED'
    },
    {
      id: 'key_exchange',
      title: 'Key Exchange',
      description: 'Exchange encryption keys securely',
      stage: 'KEY_EXCHANGE_COMPLETE'
    },
    {
      id: 'finished',
      title: 'Handshake Finished',
      description: 'Confirm secure channel establishment',
      stage: 'HANDSHAKE_COMPLETE'
    }
  ];

  const getStepStatus = (step) => {
    const currentStageIndex = handshakeSteps.findIndex(s => s.stage === tlsHandshakeStatus.stage);
    const stepIndex = handshakeSteps.findIndex(s => s.id === step.id);
    
    if (tlsHandshakeStatus.stage === 'FAILED') {
      return stepIndex <= currentStageIndex ? 'failed' : 'pending';
    }
    
    if (stepIndex < currentStageIndex || tlsHandshakeStatus.completed) {
      return 'completed';
    } else if (stepIndex === currentStageIndex) {
      return 'active';
    } else {
      return 'pending';
    }
  };

  const addToLog = (message, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setHandshakeLog(prev => [...prev, { message, type, timestamp }]);
  };

  const handleStartHandshake = async () => {
    setIsPerformingHandshake(true);
    setHandshakeLog([]);
    
    addToLog('🤝 Starting TLS handshake...', 'info');
    
    const result = await performTLSHandshake();
    
    if (result.success) {
      addToLog('✅ TLS handshake completed successfully!', 'success');
      addToLog(`🔐 Secure session established: ${result.sessionId}`, 'success');
    } else {
      addToLog(`❌ TLS handshake failed: ${result.message}`, 'error');
    }
    
    setIsPerformingHandshake(false);
  };

  const handleResetHandshake = () => {
    resetHandshake();
    setHandshakeLog([]);
    addToLog('🔄 Handshake reset', 'info');
  };

  const handleSimulateDowngradeAttack = async () => {
    addToLog('⚠️ Simulating downgrade attack...', 'warning');
    
    const result = await simulateAttack('downgrade', {
      originalVersion: 'TLS1.3',
      attackVersion: 'TLS1.0'
    });
    
    if (result.success) {
      addToLog('🚨 Downgrade attack detected and blocked!', 'error');
    } else {
      addToLog('❌ Failed to simulate attack', 'error');
    }
  };

  const handleSimulateFakeCertificateAttack = async () => {
    addToLog('⚠️ Simulating fake certificate attack...', 'warning');
    
    const result = await simulateAttack('certificate', {
      reason: 'Invalid certificate signature - potential fake certificate'
    });
    
    if (result.success) {
      addToLog('🚨 Fake certificate detected and blocked!', 'error');
    } else {
      addToLog('❌ Failed to simulate certificate attack', 'error');
    }
  };

  const handleSimulateReplayAttack = async () => {
    addToLog('⚠️ Simulating replay attack...', 'warning');
    
    const result = await simulateAttack('replay', {
      messageHash: 'duplicate_message_hash_' + Date.now()
    });
    
    if (result.success) {
      addToLog('🚨 Replay attack detected and blocked!', 'error');
    } else {
      addToLog('❌ Failed to simulate replay attack', 'error');
    }
  };

  const parseCertificate = (certString) => {
    try {
      return JSON.parse(certString);
    } catch {
      return null;
    }
  };

  const certificate = parseCertificate(serverCertificate);

  return (
    <div className="min-h-screen gradient-bg">
      {/* Navigation Header */}
      <nav className="glass-dark border-b border-gray-700 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <div className="h-10 w-10 flex items-center justify-center rounded-xl bg-gradient-to-r from-primary-500 to-primary-600 shadow-glow mr-4">
                <ShieldCheckIcon className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">SecureChat</h1>
                <p className="text-xs text-gray-400">TLS Security Protocol</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-gray-300">Welcome, {user?.username}</span>
              <Link
                to="/messaging"
                className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  tlsHandshakeStatus.completed 
                    ? 'bg-blue-600 text-white hover:bg-blue-700' 
                    : 'bg-gray-600 text-gray-400 cursor-not-allowed'
                }`}
                {...(!tlsHandshakeStatus.completed && { onClick: (e) => e.preventDefault() })}
              >
                <ChatBubbleLeftRightIcon className="h-4 w-4 inline mr-2" />
                Secure Messaging
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

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8 animate-slideInDown">
          <div className="text-center lg:text-left">
            <h2 className="text-4xl font-bold text-white mb-4">
              <span className="bg-gradient-to-r from-primary-300 to-primary-500 bg-clip-text text-transparent">
                TLS Handshake Protocol
              </span>
            </h2>
            <p className="text-lg text-gray-300 max-w-2xl">
              Establish a secure, encrypted communication channel using Transport Layer Security
            </p>
            <div className="mt-4 flex items-center justify-center lg:justify-start space-x-6 text-sm text-gray-400">
              <div className="flex items-center">
                <div className="h-2 w-2 bg-success-500 rounded-full mr-2"></div>
                RSA-2048 Key Exchange
              </div>
              <div className="flex items-center">
                <div className="h-2 w-2 bg-primary-500 rounded-full mr-2"></div>
                AES-256-CBC Encryption
              </div>
              <div className="flex items-center">
                <div className="h-2 w-2 bg-warning-500 rounded-full mr-2"></div>
                X.509 Certificates
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Column - Handshake Steps */}
          <div className="lg:col-span-2">
            <div className="security-card">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-bold text-white">Handshake Process</h2>
                <div className="flex space-x-2">
                  <button
                    onClick={handleStartHandshake}
                    disabled={isPerformingHandshake || tlsHandshakeStatus.completed}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors duration-200 ${
                      isPerformingHandshake || tlsHandshakeStatus.completed
                        ? 'bg-gray-600 text-gray-400 cursor-not-allowed'
                        : 'bg-blue-600 hover:bg-blue-700 text-white'
                    }`}
                  >
                    {isPerformingHandshake ? (
                      <>
                        <ArrowPathIcon className="h-4 w-4 mr-2 inline animate-spin" />
                        Performing...
                      </>
                    ) : tlsHandshakeStatus.completed ? (
                      <>
                        <CheckCircleIcon className="h-4 w-4 mr-2 inline" />
                        Completed
                      </>
                    ) : (
                      <>
                        <ShieldCheckIcon className="h-4 w-4 mr-2 inline" />
                        Start Handshake
                      </>
                    )}
                  </button>
                  
                  {(tlsHandshakeStatus.stage !== 'NOT_STARTED' || handshakeLog.length > 0) && (
                    <button
                      onClick={handleResetHandshake}
                      className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg text-sm font-medium transition-colors duration-200"
                    >
                      <ArrowPathIcon className="h-4 w-4 mr-2 inline" />
                      Reset
                    </button>
                  )}
                </div>
              </div>

              {/* Handshake Steps */}
              <div className="space-y-4">
                {handshakeSteps.map((step, index) => {
                  const status = getStepStatus(step);
                  return (
                    <div
                      key={step.id}
                      className={`handshake-step ${status}`}
                    >
                      <div className="flex items-center">
                        <div className="flex-shrink-0">
                          {status === 'completed' ? (
                            <CheckCircleIcon className="h-6 w-6 text-green-500" />
                          ) : status === 'active' ? (
                            <ClockIcon className="h-6 w-6 text-blue-500 animate-pulse" />
                          ) : status === 'failed' ? (
                            <XCircleIcon className="h-6 w-6 text-red-500" />
                          ) : (
                            <div className="h-6 w-6 rounded-full border-2 border-gray-400"></div>
                          )}
                        </div>
                        <div className="ml-4 flex-1">
                          <h3 className="text-lg font-medium">
                            {index + 1}. {step.title}
                          </h3>
                          <p className="text-sm opacity-75">{step.description}</p>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Current Status */}
              <div className="mt-6 p-4 bg-gray-700 rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-300">Current Status</p>
                    <p className="text-lg font-bold text-white">
                      {tlsHandshakeStatus.stage.replace(/_/g, ' ')}
                    </p>
                  </div>
                  {tlsHandshakeStatus.sessionId && (
                    <div className="text-right">
                      <p className="text-sm font-medium text-gray-300">Session ID</p>
                      <p className="text-sm font-mono text-blue-400">
                        {tlsHandshakeStatus.sessionId.substring(0, 16)}...
                      </p>
                    </div>
                  )}
                </div>
              </div>

              {/* Demo Attacks */}
              <div className="mt-6 p-4 bg-red-900 border border-red-500 rounded-lg">
                <h3 className="text-lg font-bold text-red-200 mb-3">Security Testing</h3>
                <p className="text-sm text-red-300 mb-4">
                  Test the system's ability to detect and prevent attacks
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <button
                    onClick={handleSimulateDowngradeAttack}
                    className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium transition-colors duration-200"
                  >
                    <ExclamationTriangleIcon className="h-4 w-4 mr-2 inline" />
                    Downgrade Attack
                  </button>
                  <button
                    onClick={handleSimulateFakeCertificateAttack}
                    className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium transition-colors duration-200"
                  >
                    <DocumentTextIcon className="h-4 w-4 mr-2 inline" />
                    Fake Certificate
                  </button>
                  <button
                    onClick={handleSimulateReplayAttack}
                    className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium transition-colors duration-200"
                  >
                    <ArrowPathIcon className="h-4 w-4 mr-2 inline" />
                    Replay Attack
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column - Details */}
          <div className="space-y-6">
            {/* Handshake Log */}
            <div className="security-card">
              <h3 className="text-lg font-bold text-white mb-4">Handshake Log</h3>
              <div className="space-y-2 max-h-64 overflow-y-auto custom-scrollbar">
                {handshakeLog.length > 0 ? (
                  handshakeLog.map((entry, index) => (
                    <div
                      key={index}
                      className={`p-2 rounded text-sm ${
                        entry.type === 'success' ? 'bg-green-900 text-green-200' :
                        entry.type === 'error' ? 'bg-red-900 text-red-200' :
                        entry.type === 'warning' ? 'bg-yellow-900 text-yellow-200' :
                        'bg-gray-700 text-gray-300'
                      }`}
                    >
                      <div className="flex justify-between items-start">
                        <span>{entry.message}</span>
                        <span className="text-xs opacity-75 ml-2">{entry.timestamp}</span>
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="text-gray-400 text-sm text-center py-4">
                    No handshake activity yet
                  </p>
                )}
              </div>
            </div>

            {/* Key Information */}
            <div className="security-card">
              <h3 className="text-lg font-bold text-white mb-4">Cryptographic Keys</h3>
              <div className="space-y-3">
                <div>
                  <div className="flex items-center mb-2">
                    <KeyIcon className="h-4 w-4 text-blue-400 mr-2" />
                    <span className="text-sm font-medium text-gray-300">Client RSA Key Pair</span>
                  </div>
                  <div className={`text-xs p-2 rounded ${keyPair ? 'bg-green-900 text-green-200' : 'bg-red-900 text-red-200'}`}>
                    {keyPair ? '✓ Generated (2048-bit)' : '✗ Not available'}
                  </div>
                </div>

                {sessionKey && (
                  <div>
                    <div className="flex items-center mb-2">
                      <KeyIcon className="h-4 w-4 text-green-400 mr-2" />
                      <span className="text-sm font-medium text-gray-300">Session Key</span>
                    </div>
                    <div className="crypto-key">
                      {sessionKey.substring(0, 32)}...
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Server Certificate */}
            {certificate && (
              <div className="security-card">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-bold text-white">Server Certificate</h3>
                  <button
                    onClick={() => setShowCertificateDetails(!showCertificateDetails)}
                    className="text-blue-400 hover:text-blue-300 text-sm"
                  >
                    {showCertificateDetails ? 'Hide' : 'Show'} Details
                  </button>
                </div>
                
                <div className="space-y-2">
                  <div className="flex items-center">
                    <DocumentTextIcon className="h-4 w-4 text-green-400 mr-2" />
                    <span className="text-sm text-gray-300">Valid Certificate</span>
                  </div>
                  
                  <div className="text-xs text-gray-400">
                    <p><strong>Subject:</strong> {certificate.subject?.commonName}</p>
                    <p><strong>Issuer:</strong> {certificate.issuer?.organization}</p>
                    <p><strong>Valid Until:</strong> {new Date(certificate.validTo).toLocaleDateString()}</p>
                  </div>

                  {showCertificateDetails && (
                    <div className="mt-4 p-3 bg-gray-700 rounded">
                      <h4 className="text-sm font-medium text-gray-300 mb-2">Certificate Details</h4>
                      <div className="crypto-key max-h-32 overflow-y-auto">
                        {JSON.stringify(certificate, null, 2)}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Security Features */}
            <div className="security-card">
              <h3 className="text-lg font-bold text-white mb-4">Security Features</h3>
              <div className="space-y-2 text-sm">
                <div className="flex items-center">
                  <CheckCircleIcon className="h-4 w-4 text-green-400 mr-2" />
                  <span className="text-gray-300">TLS 1.3 Protocol</span>
                </div>
                <div className="flex items-center">
                  <CheckCircleIcon className="h-4 w-4 text-green-400 mr-2" />
                  <span className="text-gray-300">Perfect Forward Secrecy</span>
                </div>
                <div className="flex items-center">
                  <CheckCircleIcon className="h-4 w-4 text-green-400 mr-2" />
                  <span className="text-gray-300">Certificate Validation</span>
                </div>
                <div className="flex items-center">
                  <CheckCircleIcon className="h-4 w-4 text-green-400 mr-2" />
                  <span className="text-gray-300">Downgrade Attack Protection</span>
                </div>
                <div className="flex items-center">
                  <CheckCircleIcon className="h-4 w-4 text-green-400 mr-2" />
                  <span className="text-gray-300">Strong Cipher Suites</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TLSHandshake;
