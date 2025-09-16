import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { cryptoService } from '../services/cryptoService';

const CryptoContext = createContext();

export const useCrypto = () => {
  const context = useContext(CryptoContext);
  if (!context) {
    throw new Error('useCrypto must be used within a CryptoProvider');
  }
  return context;
};

export const CryptoProvider = ({ children }) => {
  const [keyPair, setKeyPair] = useState(null);
  const [serverPublicKey, setServerPublicKey] = useState(null);
  const [serverCertificate, setServerCertificate] = useState(null);
  const [sessionKey, setSessionKey] = useState(null);
  const [tlsHandshakeStatus, setTlsHandshakeStatus] = useState({
    stage: 'NOT_STARTED',
    sessionId: null,
    completed: false
  });

  const validateServerCertificate = async (certString) => {
    try {
      const cert = JSON.parse(certString);
      const now = new Date();
      
      if (!cert.subject || !cert.issuer || !cert.publicKey || !cert.validFrom || !cert.validTo || !cert.signature) {
        return { valid: false, reason: 'Invalid certificate structure' };
      }
      
      const validFrom = new Date(cert.validFrom);
      const validTo = new Date(cert.validTo);
      if (now < validFrom) {
        return { valid: false, reason: 'Certificate not yet valid' };
      }
      if (now > validTo) {
        return { valid: false, reason: 'Certificate has expired' };
      }
      
      if (!cert.subject.commonName || cert.subject.commonName !== 'SecureMessaging-Server') {
        return { valid: false, reason: 'Invalid certificate subject' };
      }
      
      if (!cert.extensions || !cert.extensions.keyUsage) {
        return { valid: false, reason: 'Missing key usage extensions' };
      }
      const requiredKeyUsages = ['digitalSignature', 'keyEncipherment'];
      const hasRequiredUsages = requiredKeyUsages.every(usage => 
        cert.extensions.keyUsage.includes(usage)
      );
      if (!hasRequiredUsages) {
        return { valid: false, reason: 'Invalid key usage extensions' };
      }
      if (!cert.extensions.extKeyUsage || !cert.extensions.extKeyUsage.includes('serverAuth')) {
        return { valid: false, reason: 'Certificate not valid for server authentication' };
      }

      const certDataForSigning = JSON.stringify({
        version: cert.version,
        serialNumber: cert.serialNumber,
        issuer: cert.issuer,
        subject: cert.subject,
        publicKey: cert.publicKey,
        validFrom: cert.validFrom,
        validTo: cert.validTo,
        extensions: cert.extensions
      });
      const signatureValid = await cryptoService.rsaVerifySignature(
        certDataForSigning,
        cert.signature,
        cert.publicKey
      );
      if (!signatureValid) {
        return { valid: false, reason: 'Invalid certificate signature' };
      }

      return { valid: true, reason: 'Certificate is valid' };
    } catch (error) {
      return { valid: false, reason: `Certificate parsing error: ${error.message}` };
    }
  };

  const generateClientKeyPair = useCallback(async () => {
    try {
      const newKeyPair = await cryptoService.generateRSAKeyPair();
      setKeyPair(newKeyPair);
      console.log('🔑 Client RSA key pair generated');
    } catch (error) {
      console.error('❌ Error generating client key pair:', error);
    }
  }, []);

  useEffect(() => {
    generateClientKeyPair();
  }, [generateClientKeyPair]);

  const performTLSHandshake = async () => {
    try {
      setTlsHandshakeStatus({ stage: 'STARTING', sessionId: null, completed: false });

      const clientHello = {
        version: 'TLS1.3',
        clientRandom: cryptoService.generateRandomHex(32),
        cipherSuites: [
          'TLS_AES_256_GCM_SHA384',
          'TLS_CHACHA20_POLY1305_SHA256',
          'TLS_AES_128_GCM_SHA256'
        ],
        extensions: {
          serverName: 'SecureMessaging-Server',
          supportedVersions: ['TLS1.3', 'TLS1.2']
        }
      };

      const serverHelloResponse = await cryptoService.performTLSHandshake('client-hello', {
        clientHello
      });

      if (!serverHelloResponse.success) {
        throw new Error(serverHelloResponse.message || 'TLS handshake failed');
      }

      setTlsHandshakeStatus({
        stage: 'SERVER_HELLO_RECEIVED',
        sessionId: serverHelloResponse.sessionId,
        completed: false
      });

      const certResponse = await cryptoService.performTLSHandshake('certificate', {
        sessionId: serverHelloResponse.sessionId
      });

      if (!certResponse.success) {
        throw new Error(certResponse.message || 'Certificate exchange failed');
      }

      const certValidation = await validateServerCertificate(certResponse.certificate);
      if (!certValidation.valid) {
        throw new Error(`Certificate validation failed: ${certValidation.reason}`);
      }

      const certificate = JSON.parse(certResponse.certificate);
      const publicKeyFromCertificate = certificate.publicKey;

      setServerCertificate(certResponse.certificate);
      setServerPublicKey(publicKeyFromCertificate);

      setTlsHandshakeStatus({
        stage: 'CERTIFICATE_RECEIVED',
        sessionId: serverHelloResponse.sessionId,
        completed: false
      });

      const preMasterSecret = cryptoService.generateRandomHex(48);
      const encryptedPreMasterSecret = await cryptoService.rsaEncrypt(
        preMasterSecret,
        publicKeyFromCertificate
      );

      const keyExchangeResponse = await cryptoService.performTLSHandshake('key-exchange', {
        sessionId: serverHelloResponse.sessionId,
        keyExchangeMethod: 'RSA',
        clientKeyShare: encryptedPreMasterSecret
      });

      if (!keyExchangeResponse.success) {
        throw new Error(keyExchangeResponse.message || 'Key exchange failed');
      }

      setTlsHandshakeStatus({
        stage: 'KEY_EXCHANGE_COMPLETE',
        sessionId: serverHelloResponse.sessionId,
        completed: false
      });

      const sharedSecret = cryptoService.sha256(
        preMasterSecret + clientHello.clientRandom + serverHelloResponse.serverRandom
      );
      const masterSecret = cryptoService.sha256(
        sharedSecret + 'master secret' + clientHello.clientRandom + serverHelloResponse.serverRandom
      );
      const clientFinished = cryptoService.sha256(masterSecret + 'client finished');

      const finishedResponse = await cryptoService.performTLSHandshake('finished', {
        sessionId: serverHelloResponse.sessionId,
        clientFinished
      });

      if (!finishedResponse.success) {
        throw new Error(finishedResponse.message || 'Handshake finish failed');
      }

      setSessionKey(finishedResponse.sessionKey);
      setTlsHandshakeStatus({
        stage: 'HANDSHAKE_COMPLETE',
        sessionId: serverHelloResponse.sessionId,
        completed: true
      });

      console.log('✅ TLS Handshake completed successfully');
      return { success: true, sessionId: serverHelloResponse.sessionId };

    } catch (error) {
      console.error('❌ TLS Handshake error:', error);
      setTlsHandshakeStatus({
        stage: 'FAILED',
        sessionId: null,
        completed: false,
        error: error.message
      });
      return { success: false, message: error.message };
    }
  };

  const encryptMessage = async (message) => {
    try {
      if (!sessionKey) {
        throw new Error('No session key available. Please complete TLS handshake first.');
      }

      const encrypted = await cryptoService.aesEncrypt(message, sessionKey);
      const signature = await cryptoService.signData(message, keyPair.privateKey);

      return {
        success: true,
        encryptedMessage: encrypted.encrypted,
        iv: encrypted.iv,
        signature
      };
    } catch (error) {
      console.error('❌ Message encryption error:', error);
      return { success: false, message: error.message };
    }
  };

  const decryptMessage = async (encryptedMessage, iv, signature) => {
    try {
      if (!sessionKey) {
        throw new Error('No session key available. Please complete TLS handshake first.');
      }

      const decrypted = await cryptoService.aesDecrypt(encryptedMessage, sessionKey, iv);
      
      const isValidSignature = await cryptoService.verifySignature(
        decrypted,
        signature,
        serverPublicKey
      );

      if (!isValidSignature) {
        throw new Error('Invalid message signature');
      }

      return {
        success: true,
        decryptedMessage: decrypted,
        signatureValid: true
      };
    } catch (error) {
      console.error('❌ Message decryption error:', error);
      return { success: false, message: error.message };
    }
  };

  const resetHandshake = () => {
    setTlsHandshakeStatus({
      stage: 'NOT_STARTED',
      sessionId: null,
      completed: false
    });
    setSessionKey(null);
    setServerCertificate(null);
  };

  const value = {
    keyPair,
    serverPublicKey,
    serverCertificate,
    sessionKey,
    tlsHandshakeStatus,
    performTLSHandshake,
    encryptMessage,
    decryptMessage,
    resetHandshake,
    generateClientKeyPair
  };

  return (
    <CryptoContext.Provider value={value}>
      {children}
    </CryptoContext.Provider>
  );
};
