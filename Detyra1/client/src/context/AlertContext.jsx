 import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { alertService } from '../services/alertService';
import { useAuth } from './AuthContext';

const AlertContext = createContext();

export const useAlert = () => {
  const context = useContext(AlertContext);
  if (!context) {
    throw new Error('useAlert must be used within an AlertProvider');
  }
  return context;
};

export const AlertProvider = ({ children }) => {
  const { user } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [statistics, setStatistics] = useState({});
  const [loading, setLoading] = useState(false);

  const fetchAlerts = useCallback(async (filter = {}) => {
    try {
      setLoading(true);
      const response = await alertService.getAlerts(filter);
      
      if (response.success) {
        setAlerts(response.alerts);
      }
    } catch (error) {
      console.error('❌ Error fetching alerts:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchStatistics = useCallback(async () => {
    try {
      const response = await alertService.getStatistics();
      
      if (response.success) {
        setStatistics(response.statistics);
      }
    } catch (error) {
      console.error('❌ Error fetching alert statistics:', error);
    }
  }, []);

  useEffect(() => {
    if (user) {
      fetchAlerts();
      fetchStatistics();
      
      const interval = setInterval(() => {
        fetchAlerts();
        fetchStatistics();
      }, 30000); // Refresh every 30 seconds

      return () => clearInterval(interval);
    }
  }, [user, fetchAlerts, fetchStatistics]);

  const resolveAlert = useCallback(async (alertId) => {
    try {
      const response = await alertService.resolveAlert(alertId);
      
      if (response.success) {
        setAlerts(prevAlerts => 
          prevAlerts.map(alert => 
            alert.id === alertId 
              ? { ...alert, resolved: true, resolvedAt: new Date().toISOString() }
              : alert
          )
        );
        
        fetchStatistics();
        
        return { success: true };
      }
      
      return { success: false, message: response.message };
    } catch (error) {
      console.error('❌ Error resolving alert:', error);
      return { success: false, message: error.message };
    }
  }, [fetchStatistics]);

  const clearAlerts = useCallback(async (filter = {}) => {
    try {
      const response = await alertService.clearAlerts(filter);
      
      if (response.success) {
        await fetchAlerts();
        await fetchStatistics();
        
        return { success: true };
      }
      
      return { success: false, message: response.message };
    } catch (error) {
      console.error('❌ Error clearing alerts:', error);
      return { success: false, message: error.message };
    }
  }, [fetchAlerts, fetchStatistics]);

  const createTestAlert = useCallback(async (type, description, context = {}) => {
    try {
      const response = await alertService.createTestAlert(type, description, context);
      
      if (response.success) {
        await fetchAlerts();
        await fetchStatistics();
        
        return { success: true, alert: response.alert };
      }
      
      return { success: false, message: response.message };
    } catch (error) {
      console.error('❌ Error creating test alert:', error);
      return { success: false, message: error.message };
    }
  }, [fetchAlerts, fetchStatistics]);

  const simulateAttack = useCallback(async (attackType, parameters = {}) => {
    try {
      const response = await alertService.simulateAttack(attackType, parameters);
      
      if (response.success) {
        await fetchAlerts();
        await fetchStatistics();
        
        return { success: true, alert: response.alert };
      }
      
      return { success: false, message: response.message };
    } catch (error) {
      console.error('❌ Error simulating attack:', error);
      return { success: false, message: error.message };
    }
  }, [fetchAlerts, fetchStatistics]);

  const getSecurityDashboard = useCallback(async () => {
    try {
      const response = await alertService.getSecurityDashboard();
      
      if (response.success) {
        return { success: true, dashboard: response.dashboard };
      }
      
      return { success: false, message: response.message };
    } catch (error) {
      console.error('❌ Error fetching security dashboard:', error);
      return { success: false, message: error.message };
    }
  }, []);

  const exportAlerts = useCallback(async (format = 'json', filter = {}) => {
    try {
      const response = await alertService.exportAlerts(format, filter);
      
      if (response.success || response.data) {
        const blob = new Blob([JSON.stringify(response.data || response, null, 2)], {
          type: format === 'csv' ? 'text/csv' : 'application/json'
        });
        
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `security_alerts.${format}`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        
        return { success: true };
      }
      
      return { success: false, message: 'Export failed' };
    } catch (error) {
      console.error('❌ Error exporting alerts:', error);
      return { success: false, message: error.message };
    }
  }, []);

  const getCriticalAlerts = useCallback(() => {
    return alerts.filter(alert => 
      alert.level === 'fatal' && !alert.resolved
    );
  }, [alerts]);

  const getRecentAlerts = useCallback((hours = 24) => {
    const cutoff = new Date(Date.now() - hours * 60 * 60 * 1000);
    return alerts.filter(alert => 
      new Date(alert.timestamp) > cutoff
    );
  }, [alerts]);

  const getAlertsByType = useCallback((type) => {
    return alerts.filter(alert => alert.type === type);
  }, [alerts]);

  const getUnresolvedAlerts = useCallback(() => {
    return alerts.filter(alert => !alert.resolved);
  }, [alerts]);

  const value = {
    alerts,
    statistics,
    loading,
    fetchAlerts,
    fetchStatistics,
    resolveAlert,
    clearAlerts,
    createTestAlert,
    simulateAttack,
    getSecurityDashboard,
    exportAlerts,
    getCriticalAlerts,
    getRecentAlerts,
    getAlertsByType,
    getUnresolvedAlerts
  };

  return (
    <AlertContext.Provider value={value}>
      {children}
    </AlertContext.Provider>
  );
};
