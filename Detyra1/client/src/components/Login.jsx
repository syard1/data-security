import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useCrypto } from '../context/CryptoContext';
import { EyeIcon, EyeSlashIcon, LockClosedIcon, UserIcon, ShieldCheckIcon } from '@heroicons/react/24/outline';

const Login = () => {
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [tlsRequired, setTlsRequired] = useState(true);
  
  const { login, error, setError } = useAuth();
  const { tlsHandshakeStatus, sessionKey, performTLSHandshake } = useCrypto();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    if (error) {
      setError(null);
    }
  };

  const handleTLSHandshake = async () => {
    setIsLoading(true);
    try {
      const result = await performTLSHandshake();
      if (!result.success) {
        setError(result.message || 'TLS handshake failed');
      }
    } catch (error) {
      setError('TLS handshake failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!formData.username || !formData.password) {
      setError('Please fill in all fields');
      return;
    }

    if (!tlsHandshakeStatus.completed || !sessionKey) {
      setError('Please complete TLS handshake first');
      return;
    }

    setIsLoading(true);
    
    try {
      const result = await login(
        formData.username, 
        formData.password, 
        tlsHandshakeStatus.sessionId, 
        sessionKey
      );
      
      if (!result.success) {
        setError(result.message || 'Login failed');
      }
    } catch (error) {
      setError('An unexpected error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center gradient-bg">
      <div className="max-w-md w-full space-y-8 p-8 animate-slideInUp">
        <div className="glass-effect rounded-2xl p-8 hover:shadow-glow transition-all duration-300">
          <div className="text-center">
            <div className="mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-gradient-to-r from-primary-500 to-primary-600 shadow-glow mb-6">
              <ShieldCheckIcon className="h-8 w-8 text-white" />
            </div>
            <h2 className="text-3xl font-bold text-white mb-2">Secure Login</h2>
            <p className="text-gray-400">Access your encrypted messaging platform</p>
          </div>

          {error && (
            <div className="mt-4 p-4 bg-red-900 border border-red-500 rounded-lg">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <p className="text-sm text-red-200">{error}</p>
                </div>
              </div>
            </div>
          )}

          <div className="mt-6 p-4 bg-blue-900 border border-blue-500 rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-medium text-blue-200">TLS Handshake Status</h3>
                <p className="text-xs text-blue-300 mt-1">
                  {tlsHandshakeStatus.completed ? 'Secure channel established' : 'Secure channel required'}
                </p>
              </div>
              <div className="flex items-center">
                {tlsHandshakeStatus.completed ? (
                  <div className="h-3 w-3 bg-green-400 rounded-full animate-pulse"></div>
                ) : (
                  <button
                    onClick={handleTLSHandshake}
                    disabled={isLoading}
                    className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded-md transition-colors duration-200"
                  >
                    Start TLS
                  </button>
                )}
              </div>
            </div>
          </div>

          <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
            <div className="space-y-4">
              <div>
                <label htmlFor="username" className="block text-sm font-medium text-gray-300">
                  Username
                </label>
                <div className="mt-1 relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <UserIcon className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    id="username"
                    name="username"
                    type="text"
                    autoComplete="username"
                    required
                    className="form-input pl-10"
                    placeholder="Enter your username"
                    value={formData.username}
                    onChange={handleChange}
                    disabled={isLoading}
                  />
                </div>
              </div>

              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-300">
                  Password
                </label>
                <div className="mt-1 relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <LockClosedIcon className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    id="password"
                    name="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    required
                    className="form-input pl-10 pr-10"
                    placeholder="Enter your password"
                    value={formData.password}
                    onChange={handleChange}
                    disabled={isLoading}
                  />
                  <div className="absolute inset-y-0 right-0 pr-3 flex items-center">
                    <button
                      type="button"
                      className="text-gray-400 hover:text-gray-300 focus:outline-none"
                      onClick={() => setShowPassword(!showPassword)}
                      disabled={isLoading}
                    >
                      {showPassword ? (
                        <EyeSlashIcon className="h-5 w-5" />
                      ) : (
                        <EyeIcon className="h-5 w-5" />
                      )}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={isLoading || !tlsHandshakeStatus.completed}
                className="form-button flex items-center justify-center disabled:opacity-50"
              >
                {isLoading ? (
                  <>
                    <div className="loading-spinner h-5 w-5 mr-2"></div>
                    Authenticating...
                  </>
                ) : (
                  <>
                    <LockClosedIcon className="h-5 w-5 mr-2" />
                    {tlsHandshakeStatus.completed ? 'Secure Login' : 'Complete TLS Handshake First'}
                  </>
                )}
              </button>
            </div>
          </form>

          <div className="mt-6 text-center">
            <p className="text-sm text-gray-400">
              Don't have an account?{' '}
              <Link to="/register" className="text-primary-400 hover:text-primary-300 font-medium">
                Create one here
              </Link>
            </p>
          </div>

          <div className="mt-8 pt-6 border-t border-gray-700">
            <h3 className="text-sm font-medium text-gray-300 mb-3">Security Features:</h3>
            <div className="grid grid-cols-2 gap-2 text-xs text-gray-400">
              <div className="flex items-center">
                <span className="text-green-400 mr-1">✓</span>
                RSA Key Exchange
              </div>
              <div className="flex items-center">
                <span className="text-green-400 mr-1">✓</span>
                AES-256 Encryption
              </div>
              <div className="flex items-center">
                <span className="text-green-400 mr-1">✓</span>
                TLS Handshake
              </div>
              <div className="flex items-center">
                <span className="text-green-400 mr-1">✓</span>
                Digital Signatures
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;