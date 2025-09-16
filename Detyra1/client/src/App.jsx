import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Register from './components/Register';
import TLSHandshake from './components/TLSHandshake';
import SecureMessaging from './components/SecureMessaging';
import { AuthProvider, useAuth } from './context/AuthContext';
import { CryptoProvider } from './context/CryptoContext';
import { AlertProvider } from './context/AlertContext';
import './App.css';

function AppContent() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen gradient-bg flex items-center justify-center">
        <div className="glass-effect rounded-2xl p-8 animate-scaleIn">
          <div className="flex flex-col items-center space-y-4">
            <div className="relative">
              <div className="animate-spin rounded-full h-16 w-16 border-4 border-primary-600 border-t-transparent"></div>
              <div className="animate-pulse absolute inset-0 rounded-full border-4 border-primary-400 opacity-20"></div>
            </div>
            <div className="text-center">
              <h3 className="text-lg font-semibold text-white mb-1">SecureChat</h3>
              <p className="text-sm text-gray-300">Initializing secure connection...</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen gradient-bg text-white">
      <Router>
        <main className="animate-fadeIn">
          <Routes>
            {!user ? (
              <>
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="*" element={<Navigate to="/login" replace />} />
              </>
            ) : (
              <>
                <Route path="/tls-handshake" element={<TLSHandshake />} />
                <Route path="/messaging" element={<SecureMessaging />} />
                <Route path="*" element={<Navigate to="/tls-handshake" replace />} />
              </>
            )}
          </Routes>
        </main>
      </Router>
    </div>
  );
}

function App() {
  return (
    <AuthProvider>
      <CryptoProvider>
        <AlertProvider>
          <AppContent />
        </AlertProvider>
      </CryptoProvider>
    </AuthProvider>
  );
}

export default App;