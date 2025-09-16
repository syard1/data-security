import { createContext, useContext, useState, useEffect } from 'react';
import { authService } from '../services/authService';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const token = localStorage.getItem('authToken');
    const userData = localStorage.getItem('userData');
    
    if (token && userData) {
      try {
        const parsedUser = JSON.parse(userData);
        setUser(parsedUser);
        authService.setAuthToken(token);
      } catch (error) {
        console.error('Error parsing stored user data:', error);
        localStorage.removeItem('authToken');
        localStorage.removeItem('userData');
      }
    }
    
    setLoading(false);
  }, []);

  const login = async (username, password, tlsSessionId, tlsSessionKey) => {
    try {
      setLoading(true);
      setError(null);
      
      if (!tlsSessionId || !tlsSessionKey) {
        throw new Error('TLS handshake must be completed before authentication');
      }

      const keyExchangeResponse = await authService.keyExchange();
      if (!keyExchangeResponse.success || !keyExchangeResponse.tlsHandshakeRequired) {
        throw new Error(keyExchangeResponse.message || 'Auth initiation failed');
      }

      const loginResponse = await authService.secureLogin(
        username, 
        password, 
        keyExchangeResponse.sessionId,
        tlsSessionId,
        tlsSessionKey
      );

      if (!loginResponse.success) {
        throw new Error(loginResponse.message || 'Login failed');
      }

      localStorage.setItem('authToken', loginResponse.token);
      localStorage.setItem('userData', JSON.stringify(loginResponse.user));
      localStorage.setItem('sessionId', loginResponse.sessionId);
      localStorage.setItem('tlsSessionId', loginResponse.tlsSessionId);
      
      setUser(loginResponse.user);
      authService.setAuthToken(loginResponse.token);
      
      return { success: true };
    } catch (error) {
      console.error('Login error:', error);
      setError(error.message);
      return { success: false, message: error.message };
    } finally {
      setLoading(false);
    }
  };

  const register = async (username, email, password) => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await authService.register(username, email, password);
      
      if (!response.success) {
        throw new Error(response.message || 'Registration failed');
      }
      
      return { success: true, message: 'Registration successful! Please log in.' };
    } catch (error) {
      console.error('Registration error:', error);
      setError(error.message);
      return { success: false, message: error.message };
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      const sessionId = localStorage.getItem('sessionId');
      if (sessionId) {
        await authService.logout(sessionId);
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('authToken');
      localStorage.removeItem('userData');
      localStorage.removeItem('sessionId');
      setUser(null);
      authService.setAuthToken(null);
    }
  };

  const value = {
    user,
    loading,
    error,
    login,
    register,
    logout,
    setError
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
