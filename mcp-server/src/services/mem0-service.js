import axios from 'axios';
import { CONFIG, ERROR_MESSAGES } from '../constants.js';

/**
 * Mem0 API Service
 * Handles all interactions with the mem0 API
 */

class Mem0Service {
  constructor(baseURL = CONFIG.MEM0_API_URL, apiKey = CONFIG.MEM0_API_KEY) {
    this.baseURL = baseURL;
    this.apiKey = apiKey;
    
    this.client = this.createClient(baseURL, apiKey);
  }

  /**
   * Create axios client with authentication and interceptors
   */
  createClient(baseURL, apiKey) {
    const headers = {
      'Content-Type': 'application/json',
    };
    
    // Add authentication if API key is provided
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
      headers['X-API-Key'] = apiKey; // Alternative header format
    }
    
    const client = axios.create({
      baseURL,
      timeout: 30000,
      headers,
    });

    // Add request interceptor for debugging and security
    client.interceptors.request.use(
      (config) => {
        if (CONFIG.SECURITY.enableAuditLogging) {
          console.log(`Mem0 API Request: ${config.method?.toUpperCase()} ${config.url}`);
        }
        return config;
      },
      (error) => {
        console.error('Mem0 API Request Error:', error);
        return Promise.reject(error);
      }
    );

    // Add response interceptor for error handling
    client.interceptors.response.use(
      (response) => {
        return response;
      },
      (error) => {
        if (error.response?.status === 401) {
          console.error('Mem0 API Authentication failed - check API key');
          throw new Error('Mem0 authentication failed');
        }
        if (error.response?.status === 403) {
          console.error('Mem0 API Access forbidden');
          throw new Error('Mem0 access forbidden');
        }
        return Promise.reject(error);
      }
    );

    return client;
  }

  /**
   * Update client configuration
   */
  updateConfig(baseURL, apiKey) {
    this.baseURL = baseURL;
    this.apiKey = apiKey;
    this.client = this.createClient(baseURL, apiKey);
  }

  /**
   * Add a memory for a user
   */
  async addMemory(userId, content, metadata = {}) {
    try {
      const response = await this.client.post('/memories', {
        messages: [{ content }],
        user_id: userId,
        metadata: {
          ...metadata,
          stored_by: userId,
          stored_at: new Date().toISOString(),
        },
      });
      
      if (CONFIG.SECURITY.enableAuditLogging) {
        console.log(`Memory created: User ${userId} stored memory ${response.data.id || 'unknown'}`);
      }
      
      return response.data;
    } catch (error) {
      console.error('Failed to add memory:', error.message);
      throw new Error(`Failed to add memory: ${error.message}`);
    }
  }

  /**
   * Search memories for a user
   */
  async searchMemories(userId, query, limit = 10) {
    try {
      const response = await this.client.post('/memories/search', {
        query,
        user_id: userId,
        limit,
      });

      const memories = response.data.memories || response.data || [];
      
      // Additional security: Verify all returned memories belong to this user
      const verifiedMemories = memories.filter(memory => {
        if (memory.user_id && memory.user_id !== userId) {
          console.warn(`Security violation: Memory ${memory.id} with user_id ${memory.user_id} returned for user ${userId}`);
          return false;
        }
        return true;
      });

      if (CONFIG.SECURITY.enableAuditLogging) {
        console.log(`Memory search: User ${userId} searched for "${query}" - ${verifiedMemories.length} results`);
      }

      return verifiedMemories;
    } catch (error) {
      console.error('Failed to search memories:', error.message);
      throw new Error(`Failed to search memories: ${error.message}`);
    }
  }

  /**
   * Get all memories for a user
   */
  async getMemories(userId, limit = 50) {
    try {
      const response = await this.client.get('/memories', {
        params: {
          user_id: userId,
          limit,
        },
      });

      const memories = response.data.memories || response.data || [];

      // Additional security: Verify all memories belong to this user
      const verifiedMemories = memories.filter(memory => {
        if (memory.user_id && memory.user_id !== userId) {
          console.warn(`Security violation: Memory ${memory.id} with user_id ${memory.user_id} returned for user ${userId}`);
          return false;
        }
        return true;
      });

      if (CONFIG.SECURITY.enableAuditLogging) {
        console.log(`Memory retrieval: User ${userId} retrieved ${verifiedMemories.length} memories`);
      }

      return verifiedMemories;
    } catch (error) {
      console.error('Failed to get memories:', error.message);
      throw new Error(`Failed to get memories: ${error.message}`);
    }
  }

  /**
   * Get a specific memory by ID
   */
  async getMemoryById(memoryId) {
    try {
      const response = await this.client.get(`/memories/${memoryId}`);
      return response.data;
    } catch (error) {
      if (error.response?.status === 404) {
        throw new Error('Memory not found');
      }
      if (error.response?.status === 403) {
        throw new Error('Access denied');
      }
      console.error('Failed to get memory:', error.message);
      throw new Error(`Failed to get memory: ${error.message}`);
    }
  }

  /**
   * Delete a memory
   */
  async deleteMemory(memoryId) {
    try {
      const response = await this.client.delete(`/memories/${memoryId}`);
      
      if (CONFIG.SECURITY.enableAuditLogging) {
        console.log(`Memory deleted: Memory ${memoryId}`);
      }
      
      return response.data;
    } catch (error) {
      console.error('Failed to delete memory:', error.message);
      throw new Error(`Failed to delete memory: ${error.message}`);
    }
  }

  /**
   * Update a memory
   */
  async updateMemory(memoryId, content, metadata = {}) {
    try {
      const response = await this.client.put(`/memories/${memoryId}`, {
        content,
        metadata: {
          ...metadata,
          updated_at: new Date().toISOString(),
        },
      });
      
      if (CONFIG.SECURITY.enableAuditLogging) {
        console.log(`Memory updated: Memory ${memoryId}`);
      }
      
      return response.data;
    } catch (error) {
      console.error('Failed to update memory:', error.message);
      throw new Error(`Failed to update memory: ${error.message}`);
    }
  }

  /**
   * Get memory statistics for a user
   */
  async getMemoryStats(userId) {
    try {
      const memories = await this.getMemories(userId, 1000);
      
      const stats = {
        total: memories.length,
        categories: {},
        recent: memories.slice(0, 5),
        byDate: {},
      };

      // Count by categories
      memories.forEach(memory => {
        const category = memory.metadata?.category || 'uncategorized';
        stats.categories[category] = (stats.categories[category] || 0) + 1;
        
        // Count by date
        const date = memory.created_at ? new Date(memory.created_at).toDateString() : 'unknown';
        stats.byDate[date] = (stats.byDate[date] || 0) + 1;
      });

      return stats;
    } catch (error) {
      console.error('Failed to get memory statistics:', error.message);
      throw new Error(`Failed to get memory statistics: ${error.message}`);
    }
  }

  /**
   * Test connection to mem0 API
   */
  async testConnection() {
    try {
      // Test with a simple request that should work with any valid API
      const response = await this.client.get('/health', {
        timeout: 5000,
      });
      return { success: true, message: 'Connection successful', data: response.data };
    } catch (error) {
      // If /health doesn't exist, try a memories request
      try {
        await this.client.get('/memories', {
          params: { user_id: 'test-connection', limit: 1 },
          timeout: 5000,
        });
        return { success: true, message: 'Connection successful' };
      } catch (secondError) {
        console.warn('mem0 connection test failed:', secondError.message);
        return { 
          success: false, 
          message: `Connection failed: ${secondError.response?.statusText || secondError.message}`,
          status: secondError.response?.status,
        };
      }
    }
  }

  /**
   * Validate memory ownership
   */
  async validateMemoryOwnership(memoryId, userId) {
    try {
      const memory = await this.getMemoryById(memoryId);
      if (memory.user_id !== userId) {
        console.warn(`Access violation: User ${userId} attempted to access memory ${memoryId} owned by ${memory.user_id}`);
        throw new Error(ERROR_MESSAGES.ACCESS_DENIED);
      }
      return memory;
    } catch (error) {
      if (error.message.includes('Access denied')) {
        throw error;
      }
      throw new Error(ERROR_MESSAGES.MEMORY_NOT_FOUND);
    }
  }

  /**
   * Bulk operations
   */
  async bulkAddMemories(userId, memories) {
    const results = [];
    const errors = [];

    for (const memory of memories) {
      try {
        const result = await this.addMemory(userId, memory.content, memory.metadata);
        results.push(result);
      } catch (error) {
        errors.push({ memory, error: error.message });
      }
    }

    return { results, errors };
  }

  async bulkDeleteMemories(memoryIds, userId) {
    const results = [];
    const errors = [];

    for (const memoryId of memoryIds) {
      try {
        // Validate ownership first
        await this.validateMemoryOwnership(memoryId, userId);
        await this.deleteMemory(memoryId);
        results.push(memoryId);
      } catch (error) {
        errors.push({ memoryId, error: error.message });
      }
    }

    return { results, errors };
  }

  /**
   * Export user memories
   */
  async exportMemories(userId, format = 'json') {
    try {
      const memories = await this.getMemories(userId, 10000); // Get all memories
      
      const exportData = {
        exportDate: new Date().toISOString(),
        userId,
        totalMemories: memories.length,
        memories: memories.map(memory => ({
          id: memory.id,
          content: memory.content || memory.text,
          category: memory.metadata?.category,
          metadata: memory.metadata,
          createdAt: memory.created_at,
          updatedAt: memory.updated_at,
        })),
      };

      if (format === 'csv') {
        // Convert to CSV format
        const csv = this.convertToCSV(exportData.memories);
        return { format: 'csv', data: csv };
      }

      return { format: 'json', data: exportData };
    } catch (error) {
      console.error('Failed to export memories:', error.message);
      throw new Error(`Failed to export memories: ${error.message}`);
    }
  }

  /**
   * Convert memories to CSV format
   */
  convertToCSV(memories) {
    if (memories.length === 0) return 'No memories to export';

    const headers = ['ID', 'Content', 'Category', 'Created At', 'Updated At'];
    const csvRows = [headers.join(',')];

    memories.forEach(memory => {
      const row = [
        memory.id || '',
        `"${(memory.content || '').replace(/"/g, '""')}"`, // Escape quotes
        memory.category || '',
        memory.createdAt || '',
        memory.updatedAt || '',
      ];
      csvRows.push(row.join(','));
    });

    return csvRows.join('\n');
  }

  /**
   * Get service health and statistics
   */
  async getServiceHealth() {
    try {
      const connectionTest = await this.testConnection();
      
      return {
        status: connectionTest.success ? 'healthy' : 'unhealthy',
        connection: connectionTest,
        baseURL: this.baseURL,
        hasApiKey: !!this.apiKey,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      return {
        status: 'error',
        error: error.message,
        baseURL: this.baseURL,
        hasApiKey: !!this.apiKey,
        timestamp: new Date().toISOString(),
      };
    }
  }
}

export default Mem0Service;
