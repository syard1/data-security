import axios from 'axios';
import { cryptoService } from './cryptoService';

const API_BASE_URL = 'http://localhost:5001/api';

class AuthService {
  constructor() {
    this.authToken = null;
    this.setupAxiosInterceptors();
  }

  setupAxiosInterceptors() {
    axios.interceptors.request.use(
      (config) => {
        if (this.authToken) {
          config.headers.Authorization = `Bearer ${this.authToken}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    axios.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          this.authToken = null;
          localStorage.removeItem('authToken');
          localStorage.removeItem('userData');
          localStorage.removeItem('sessionId');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  setAuthToken(token) {
    this.authToken = token;
  }

  async register(username, email, password) {
    try {
      const response = await axios.post(`${API_BASE_URL}/auth/register`, {
        username,
        email,
        password
      });

      return response.data;
    } catch (error) {
      console.error('Registration error:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Registration failed'
      };
    }
  }

  async keyExchange() {
    try {
      const clientKeyPair = await cryptoService.generateRSAKeyPair();
      
      const response = await axios.post(`${API_BASE_URL}/auth/key-exchange`, {
        clientPublicKey: clientKeyPair.publicKey
      });

      if (response.data.success && response.data.tlsHandshakeRequired) {
        sessionStorage.setItem('clientPrivateKey', clientKeyPair.privateKey);
        
        return {
          ...response.data,
          clientKeyPair
        };
      }

      return response.data;
    } catch (error) {
      console.error('Auth initiation error:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Authentication initiation failed'
      };
    }
  }

  async secureLogin(username, password, sessionId, tlsSessionId, tlsSessionKey) {
    try {
      if (!tlsSessionKey) {
        throw new Error('TLS session key not available. Complete TLS handshake first.');
      }

      const credentials = JSON.stringify({ username, password });
      const encrypted = await cryptoService.aesEncrypt(credentials, tlsSessionKey);

      const response = await axios.post(`${API_BASE_URL}/auth/login`, {
        sessionId,
        tlsSessionId,
        encryptedCredentials: encrypted.encrypted,
        iv: encrypted.iv
      });

      sessionStorage.removeItem('clientPrivateKey');

      return response.data;
    } catch (error) {
      console.error('Secure login error:', error);
      
      sessionStorage.removeItem('clientPrivateKey');
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Secure login failed'
      };
    }
  }

  async logout(sessionId) {
    try {
      const response = await axios.post(`${API_BASE_URL}/auth/logout`, {
        sessionId
      });

      return response.data;
    } catch (error) {
      console.error('Logout error:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Logout failed'
      };
    }
  }

  async getUsers() {
    try {
      const response = await axios.get(`${API_BASE_URL}/auth/users`);
      return response.data;
    } catch (error) {
      console.error('Get users error:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to fetch users'
      };
    }
  }

  isAuthenticated() {
    return !!this.authToken;
  }

  getCurrentUser() {
    try {
      const userData = localStorage.getItem('userData');
      return userData ? JSON.parse(userData) : null;
    } catch (error) {
      console.error('Error parsing user data:', error);
      return null;
    }
  }

  getSessionId() {
    return localStorage.getItem('sessionId');
  }
}

export const authService = new AuthService();
