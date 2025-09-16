import axios from 'axios';

const API_BASE_URL = 'http://localhost:5001/api';

class MessageService {
  async encryptMessage(message, recipientId) {
    try {
      const response = await axios.post(`${API_BASE_URL}/messages/encrypt`, {
        message,
        recipientId
      });
      return response.data;
    } catch (error) {
      console.error('❌ Error encrypting message:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to encrypt message'
      };
    }
  }

  async decryptMessage(messageId, encryptedContent, iv, signature) {
    try {
      const response = await axios.post(`${API_BASE_URL}/messages/decrypt`, {
        messageId,
        encryptedContent,
        iv,
        signature
      });
      return response.data;
    } catch (error) {
      console.error('❌ Error decrypting message:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to decrypt message'
      };
    }
  }

  async getMessageHistory(limit = 50, offset = 0) {
    try {
      const response = await axios.get(`${API_BASE_URL}/messages/history`, {
        params: { limit, offset }
      });
      return response.data;
    } catch (error) {
      console.error('❌ Error fetching message history:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to fetch message history'
      };
    }
  }

  async getMessage(messageId) {
    try {
      const response = await axios.get(`${API_BASE_URL}/messages/${messageId}`);
      return response.data;
    } catch (error) {
      console.error('❌ Error fetching message:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to fetch message'
      };
    }
  }

  async getMessageStats() {
    try {
      const response = await axios.get(`${API_BASE_URL}/messages/stats`);
      return response.data;
    } catch (error) {
      console.error('❌ Error fetching message statistics:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to fetch message statistics'
      };
    }
  }

  async clearMessages() {
    try {
      const response = await axios.delete(`${API_BASE_URL}/messages/clear`);
      return response.data;
    } catch (error) {
      console.error('❌ Error clearing messages:', error);
      
      if (error.response?.data) {
        return error.response.data;
      }
      
      return {
        success: false,
        message: error.message || 'Failed to clear messages'
      };
    }
  }

  formatMessage(message) {
    return {
      ...message,
      formattedTimestamp: this.formatTimestamp(message.timestamp),
      isRecent: this.isRecentMessage(message.timestamp)
    };
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
      return `${diffMins}m ago`;
    } else if (diffHours < 24) {
      return `${diffHours}h ago`;
    } else if (diffDays < 7) {
      return `${diffDays}d ago`;
    } else {
      return date.toLocaleDateString();
    }
  }

  isRecentMessage(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    return diffMs < 3600000; // 1 hour in milliseconds
  }

  validateMessage(message) {
    if (!message || typeof message !== 'string') {
      return { valid: false, error: 'Message content is required' };
    }

    if (message.trim().length === 0) {
      return { valid: false, error: 'Message cannot be empty' };
    }

    if (message.length > 10000) {
      return { valid: false, error: 'Message is too long (max 10,000 characters)' };
    }

    return { valid: true };
  }

  getMessageTypeIcon(type) {
    const icons = {
      'sent': '📤',
      'received': '📥',
      'encrypted': '🔐',
      'decrypted': '🔓',
      'signed': '✍️',
      'verified': '✅',
      'error': '❌'
    };

    return icons[type] || '💬';
  }

  getEncryptionStatus(message) {
    if (message.encryptedContent && message.signature) {
      return {
        encrypted: true,
        signed: true,
        status: 'Encrypted & Signed',
        icon: '🔐',
        color: 'text-green-500'
      };
    } else if (message.encryptedContent) {
      return {
        encrypted: true,
        signed: false,
        status: 'Encrypted Only',
        icon: '🔒',
        color: 'text-yellow-500'
      };
    } else {
      return {
        encrypted: false,
        signed: false,
        status: 'Plain Text',
        icon: '📝',
        color: 'text-red-500'
      };
    }
  }

  groupMessagesByConversation(messages) {
    const conversations = {};

    messages.forEach(message => {
      const otherUserId = message.type === 'sent' ? message.recipientId : message.senderId;
      
      if (!conversations[otherUserId]) {
        conversations[otherUserId] = {
          userId: otherUserId,
          otherUser: message.otherUser,
          messages: [],
          lastMessage: null,
          unreadCount: 0
        };
      }

      conversations[otherUserId].messages.push(message);
      
      if (!conversations[otherUserId].lastMessage || 
          new Date(message.timestamp) > new Date(conversations[otherUserId].lastMessage.timestamp)) {
        conversations[otherUserId].lastMessage = message;
      }
    });

    return Object.values(conversations).sort((a, b) => 
      new Date(b.lastMessage.timestamp) - new Date(a.lastMessage.timestamp)
    );
  }

  searchMessages(messages, query) {
    if (!query || query.trim().length === 0) {
      return messages;
    }

    const searchTerm = query.toLowerCase().trim();
    
    return messages.filter(message => {
      if (message.content && message.content.toLowerCase().includes(searchTerm)) {
        return true;
      }

      if (message.otherUser && message.otherUser.username.toLowerCase().includes(searchTerm)) {
        return true;
      }

      if (message.messageId && message.messageId.toLowerCase().includes(searchTerm)) {
        return true;
      }

      return false;
    });
  }

  filterMessagesByDateRange(messages, startDate, endDate) {
    if (!startDate && !endDate) {
      return messages;
    }

    return messages.filter(message => {
      const messageDate = new Date(message.timestamp);
      
      if (startDate && messageDate < new Date(startDate)) {
        return false;
      }
      
      if (endDate && messageDate > new Date(endDate)) {
        return false;
      }
      
      return true;
    });
  }

  exportMessagesToJSON(messages) {
    const exportData = {
      exportDate: new Date().toISOString(),
      totalMessages: messages.length,
      messages: messages.map(message => ({
        id: message.messageId,
        type: message.type,
        timestamp: message.timestamp,
        otherUser: message.otherUser?.username,
        encrypted: !!message.encryptedContent,
        signed: !!message.signature,
        content: message.content || '[Encrypted]'
      }))
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: 'application/json'
    });

    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `messages_export_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  }
}

export const messageService = new MessageService();
