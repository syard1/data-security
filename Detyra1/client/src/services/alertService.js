import axios from 'axios';

const API_BASE_URL = 'http://localhost:5001/api';

class AlertService {
  async getAlerts(filter = {}) {
    try {
      const params = new URLSearchParams();
      
      Object.keys(filter).forEach(key => {
        if (filter[key] !== undefined && filter[key] !== '') {
          params.append(key, filter[key]);
        }
      });

      const response = await axios.get(`${API_BASE_URL}/alerts?${params.toString()}`);
      return response.data;
    } catch (error) {
      console.error('❌ Error fetching alerts:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to fetch alerts'
      };
    }
  }

  async getStatistics() {
    try {
      const response = await axios.get(`${API_BASE_URL}/alerts/statistics`);
      return response.data;
    } catch (error) {
      console.error('❌ Error fetching alert statistics:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to fetch alert statistics'
      };
    }
  }

  async getSecurityDashboard() {
    try {
      const response = await axios.get(`${API_BASE_URL}/alerts/dashboard`);
      return response.data;
    } catch (error) {
      console.error('❌ Error fetching security dashboard:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to fetch security dashboard'
      };
    }
  }

  async resolveAlert(alertId) {
    try {
      const response = await axios.put(`${API_BASE_URL}/alerts/resolve/${alertId}`);
      return response.data;
    } catch (error) {
      console.error('❌ Error resolving alert:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to resolve alert'
      };
    }
  }

  async clearAlerts(filter = {}) {
    try {
      const response = await axios.delete(`${API_BASE_URL}/alerts/clear`, {
        data: filter
      });
      return response.data;
    } catch (error) {
      console.error('❌ Error clearing alerts:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to clear alerts'
      };
    }
  }

  async createTestAlert(type, description, context = {}) {
    try {
      const response = await axios.post(`${API_BASE_URL}/alerts/test`, {
        type,
        description,
        context
      });
      return response.data;
    } catch (error) {
      console.error('❌ Error creating test alert:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to create test alert'
      };
    }
  }

  async simulateAttack(attackType, parameters = {}) {
    try {
      const response = await axios.post(`${API_BASE_URL}/alerts/simulate`, {
        attackType,
        parameters
      });
      return response.data;
    } catch (error) {
      console.error('❌ Error simulating attack:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to simulate attack'
      };
    }
  }

  async exportAlerts(format = 'json', filter = {}) {
    try {
      const params = new URLSearchParams();
      params.append('format', format);
      
      Object.keys(filter).forEach(key => {
        if (filter[key] !== undefined && filter[key] !== '') {
          params.append(key, filter[key]);
        }
      });

      const response = await axios.get(`${API_BASE_URL}/alerts/export?${params.toString()}`, {
        responseType: format === 'csv' ? 'text' : 'json'
      });

      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error('❌ Error exporting alerts:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to export alerts'
      };
    }
  }

  getAlertTypeInfo(alertType) {
    const alertTypes = {
      'CLOSE_NOTIFY': { 
        level: 'warning', 
        severity: 'low',
        description: 'Connection close notification',
        icon: '🔔'
      },
      'UNEXPECTED_MESSAGE': { 
        level: 'warning', 
        severity: 'medium',
        description: 'Unexpected message received',
        icon: '⚠️'
      },
      'BAD_RECORD_MAC': { 
        level: 'warning', 
        severity: 'medium',
        description: 'Bad record MAC detected',
        icon: '🔍'
      },
      
      'HANDSHAKE_FAILURE': { 
        level: 'fatal', 
        severity: 'high',
        description: 'TLS handshake failed',
        icon: '🤝'
      },
      'BAD_CERTIFICATE': { 
        level: 'fatal', 
        severity: 'high',
        description: 'Invalid certificate detected',
        icon: '📜'
      },
      'CERTIFICATE_EXPIRED': { 
        level: 'fatal', 
        severity: 'high',
        description: 'Certificate has expired',
        icon: '⏰'
      },
      'PROTOCOL_VERSION': { 
        level: 'fatal', 
        severity: 'high',
        description: 'Unsupported protocol version',
        icon: '🔄'
      },
      'INSUFFICIENT_SECURITY': { 
        level: 'fatal', 
        severity: 'high',
        description: 'Security level insufficient',
        icon: '🔒'
      },
      'INTERNAL_ERROR': { 
        level: 'fatal', 
        severity: 'high',
        description: 'Internal server error',
        icon: '⚙️'
      },
      
      'CERTIFICATE_ERROR': { 
        level: 'fatal', 
        severity: 'critical',
        description: 'Certificate validation error',
        icon: '🚨'
      },
      'AUTHENTICATION_FAILURE': { 
        level: 'fatal', 
        severity: 'high',
        description: 'Authentication failed',
        icon: '🔐'
      },
      'DOWNGRADE_ATTACK': { 
        level: 'fatal', 
        severity: 'critical',
        description: 'TLS downgrade attack detected',
        icon: '⬇️'
      },
      'REPLAY_ATTACK': { 
        level: 'fatal', 
        severity: 'critical',
        description: 'Message replay attack detected',
        icon: '🔄'
      },
      'MAN_IN_THE_MIDDLE': { 
        level: 'fatal', 
        severity: 'critical',
        description: 'Man-in-the-middle attack detected',
        icon: '👤'
      },
      'BRUTE_FORCE_ATTEMPT': { 
        level: 'warning', 
        severity: 'medium',
        description: 'Brute force attack attempt',
        icon: '🔨'
      },
      'SUSPICIOUS_ACTIVITY': { 
        level: 'warning', 
        severity: 'medium',
        description: 'Suspicious activity detected',
        icon: '👁️'
      },
      'ENCRYPT_ERROR': { 
        level: 'fatal', 
        severity: 'high',
        description: 'Message encryption failed',
        icon: '🔐'
      },
      'DECRYPT_ERROR': { 
        level: 'fatal', 
        severity: 'high',
        description: 'Message decryption failed',
        icon: '🔓'
      },
      'KEY_EXCHANGE_ERROR': { 
        level: 'fatal', 
        severity: 'high',
        description: 'Key exchange failed',
        icon: '🔑'
      }
    };

    return alertTypes[alertType] || {
      level: 'unknown',
      severity: 'low',
      description: 'Unknown alert type',
      icon: '❓'
    };
  }

  getSeverityColorClass(severity) {
    const colorClasses = {
      'critical': 'text-red-500 bg-red-100 border-red-500',
      'high': 'text-orange-500 bg-orange-100 border-orange-500',
      'medium': 'text-yellow-500 bg-yellow-100 border-yellow-500',
      'low': 'text-blue-500 bg-blue-100 border-blue-500',
      'unknown': 'text-gray-500 bg-gray-100 border-gray-500'
    };

    return colorClasses[severity] || colorClasses.unknown;
  }

  getLevelColorClass(level) {
    const colorClasses = {
      'fatal': 'text-red-500 bg-red-900 border-red-500',
      'warning': 'text-yellow-500 bg-yellow-900 border-yellow-500',
      'info': 'text-blue-500 bg-blue-900 border-blue-500',
      'unknown': 'text-gray-500 bg-gray-900 border-gray-500'
    };

    return colorClasses[level] || colorClasses.unknown;
  }

  formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) {
      return 'Just now';
    } else if (diffMins < 60) {
      return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
    } else if (diffHours < 24) {
      return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    } else if (diffDays < 7) {
      return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    } else {
      return date.toLocaleDateString();
    }
  }
}

export const alertService = new AlertService();
