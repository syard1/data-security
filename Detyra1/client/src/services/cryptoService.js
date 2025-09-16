import CryptoJS from 'crypto-js';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:5001/api';

class CryptoService {
  constructor() {
    this.keyPair = null;
  }

  async generateRSAKeyPair() {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256'
        },
        true,
        ['encrypt', 'decrypt']
      );

      const publicKey = await this.exportPublicKeyToPEM(keyPair.publicKey);
      const privateKey = await this.exportPrivateKeyToPEM(keyPair.privateKey);

      return {
        publicKey,
        privateKey,
        keyPair
      };
    } catch (error) {
      console.error('❌ Error generating RSA key pair:', error);
      throw error;
    }
  }

  async exportPublicKeyToPEM(publicKey) {
    const exported = await window.crypto.subtle.exportKey('spki', publicKey);
    const exportedAsString = String.fromCharCode.apply(null, new Uint8Array(exported));
    const exportedAsBase64 = window.btoa(exportedAsString);
    return `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
  }

  async exportPrivateKeyToPEM(privateKey) {
    const exported = await window.crypto.subtle.exportKey('pkcs8', privateKey);
    const exportedAsString = String.fromCharCode.apply(null, new Uint8Array(exported));
    const exportedAsBase64 = window.btoa(exportedAsString);
    return `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
  }

  async importPEMKey(pemKey, keyType = 'public') {
    try {
      const pemHeader = keyType === 'public' ? '-----BEGIN PUBLIC KEY-----' : '-----BEGIN PRIVATE KEY-----';
      const pemFooter = keyType === 'public' ? '-----END PUBLIC KEY-----' : '-----END PRIVATE KEY-----';
      
      const pemContents = pemKey
        .replace(pemHeader, '')
        .replace(pemFooter, '')
        .replace(/\s/g, '');
      
      const binaryDer = window.atob(pemContents);
      const binaryDerArray = new Uint8Array(binaryDer.length);
      
      for (let i = 0; i < binaryDer.length; i++) {
        binaryDerArray[i] = binaryDer.charCodeAt(i);
      }

      const algorithm = {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      };

      if (keyType === 'public') {
        return await window.crypto.subtle.importKey(
          'spki',
          binaryDerArray,
          algorithm,
          false,
          ['encrypt']
        );
      } else {
        return await window.crypto.subtle.importKey(
          'pkcs8',
          binaryDerArray,
          algorithm,
          false,
          ['decrypt']
        );
      }
    } catch (error) {
      console.error('❌ Error importing PEM key:', error);
      throw error;
    }
  }

  async importRSAPublicKeyForVerify(pemKey) {
    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';
    const pemContents = pemKey.replace(pemHeader, '').replace(pemFooter, '').replace(/\s/g, '');
    const binaryDer = window.atob(pemContents);
    const binaryDerArray = new Uint8Array(binaryDer.length);
    for (let i = 0; i < binaryDer.length; i++) {
      binaryDerArray[i] = binaryDer.charCodeAt(i);
    }
    return await window.crypto.subtle.importKey(
      'spki',
      binaryDerArray,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256'
      },
      false,
      ['verify']
    );
  }

  async rsaVerifySignature(data, signatureHex, publicKeyPEM) {
    try {
      const publicKey = await this.importRSAPublicKeyForVerify(publicKeyPEM);
      const encoder = new TextEncoder();
      const dataBytes = encoder.encode(data);
      const signatureBytes = this.hexToUint8Array(signatureHex);
      const valid = await window.crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' },
        publicKey,
        signatureBytes,
        dataBytes
      );
      return valid;
    } catch (error) {
      console.error('❌ RSA signature verification error:', error);
      return false;
    }
  }

  async rsaEncrypt(data, publicKeyPEM) {
    try {
      const publicKey = await this.importPEMKey(publicKeyPEM, 'public');
      const encodedData = new TextEncoder().encode(data);
      
      const encrypted = await window.crypto.subtle.encrypt(
        {
          name: 'RSA-OAEP'
        },
        publicKey,
        encodedData
      );

      return window.btoa(String.fromCharCode.apply(null, new Uint8Array(encrypted)));
    } catch (error) {
      console.error('❌ RSA encryption error:', error);
      throw error;
    }
  }

  async rsaDecrypt(encryptedData, privateKeyPEM) {
    try {
      const privateKey = await this.importPEMKey(privateKeyPEM, 'private');
      const encryptedBytes = new Uint8Array(
        window.atob(encryptedData)
          .split('')
          .map(char => char.charCodeAt(0))
      );
      
      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: 'RSA-OAEP'
        },
        privateKey,
        encryptedBytes
      );

      return new TextDecoder().decode(decrypted);
    } catch (error) {
      console.error('❌ RSA decryption error:', error);
      throw error;
    }
  }

  async aesEncrypt(data, key) {
    try {
      const iv = CryptoJS.lib.WordArray.random(16);
      const keyHash = CryptoJS.SHA256(key);
      
      const encrypted = CryptoJS.AES.encrypt(data, keyHash, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });

      return {
        encrypted: encrypted.toString(),
        iv: iv.toString(CryptoJS.enc.Hex)
      };
    } catch (error) {
      console.error('❌ AES encryption error:', error);
      throw error;
    }
  }

  async aesDecrypt(encryptedData, key, ivHex) {
    try {
      const keyHash = CryptoJS.SHA256(key);
      const iv = CryptoJS.enc.Hex.parse(ivHex);
      
      const decrypted = CryptoJS.AES.decrypt(encryptedData, keyHash, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });

      return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
      console.error('❌ AES decryption error:', error);
      throw error;
    }
  }

  async signData(data, privateKey) {
    try {
      const keyHash = CryptoJS.SHA256(privateKey);
      const signature = CryptoJS.HmacSHA256(data, keyHash);
      return signature.toString(CryptoJS.enc.Hex);
    } catch (error) {
      console.error('❌ Signing error:', error);
      throw error;
    }
  }

  async verifySignature(data, signature, publicKey) {
    try {
      const keyHash = CryptoJS.SHA256(publicKey);
      const expectedSignature = CryptoJS.HmacSHA256(data, keyHash);
      return expectedSignature.toString(CryptoJS.enc.Hex) === signature;
    } catch (error) {
      console.error('❌ Signature verification error:', error);
      return false;
    }
  }

  generateRandomHex(length) {
    const bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  sha256(data) {
    return CryptoJS.SHA256(data).toString(CryptoJS.enc.Hex);
  }

  async performTLSHandshake(step, data) {
    console.log("performing tls handshake", step, data);
    try {
      const response = await axios.post(`${API_BASE_URL}/tls/handshake/${step}`, data);
      return response.data;
    } catch (error) {
      console.error(`❌ TLS handshake ${step} error:`, error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || `TLS handshake ${step} failed`
      };
    }
  }

  async getTLSSupported() {
    try {
      const response = await axios.get(`${API_BASE_URL}/tls/supported`);
      return response.data;
    } catch (error) {
      console.error('❌ Error getting TLS supported configurations:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to get TLS configurations'
      };
    }
  }

  async simulateDowngradeAttack(originalVersion, attackVersion, cipherSuites) {
    try {
      const response = await axios.post(`${API_BASE_URL}/tls/demo/downgrade-attack`, {
        originalVersion,
        attackVersion,
        cipherSuites
      });
      return response.data;
    } catch (error) {
      console.error('❌ Error simulating downgrade attack:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Downgrade attack simulation failed'
      };
    }
  }

  stringToHex(str) {
    return Array.from(str)
      .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
      .join('');
  }

  hexToString(hex) {
    return hex.match(/.{1,2}/g)
      .map(byte => String.fromCharCode(parseInt(byte, 16)))
      .join('');
  }

  hexToUint8Array(hex) {
    if (!hex || typeof hex !== 'string') return new Uint8Array();
    const cleanHex = hex.replace(/^0x/, '');
    const pairs = cleanHex.match(/.{1,2}/g) || [];
    const bytes = new Uint8Array(pairs.length);
    for (let i = 0; i < pairs.length; i++) {
      bytes[i] = parseInt(pairs[i], 16);
    }
    return bytes;
  }

  generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}

export const cryptoService = new CryptoService();
