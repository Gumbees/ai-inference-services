import { promises as fs } from 'fs';
import path from 'path';
import { z } from 'zod';
import { CONFIG, CONFIG_SCHEMA, ENV_MAPPINGS, DEFAULT_CONFIG } from './constants.js';

/**
 * Configuration Manager for Gumbees MCP Server
 * Handles mem0 and system configuration with environment variable precedence
 */

// Configuration schemas for validation
const Mem0ConfigSchema = z.object({
  apiUrl: z.string().url().optional(),
  apiKey: z.string().min(1).optional(),
  
  // LLM Configuration
  llm: z.object({
    provider: z.enum(['openai', 'anthropic', 'openrouter', 'ollama', 'azure']).default('openai'),
    model: z.string().default('gpt-3.5-turbo'),
    apiKey: z.string().optional(),
    apiBase: z.string().url().optional(),
    temperature: z.number().min(0).max(2).default(0.1),
    maxTokens: z.number().min(1).max(32000).default(1000),
    topP: z.number().min(0).max(1).default(1),
    frequencyPenalty: z.number().min(-2).max(2).default(0),
    presencePenalty: z.number().min(-2).max(2).default(0),
  }).default({}),
  
  // Embedding Configuration
  embedder: z.object({
    provider: z.enum(['openai', 'huggingface', 'ollama', 'azure']).default('openai'),
    model: z.string().default('text-embedding-3-small'),
    apiKey: z.string().optional(),
    apiBase: z.string().url().optional(),
    dimensions: z.number().min(1).max(3072).optional(),
    chunkSize: z.number().min(100).max(8000).default(1000),
    chunkOverlap: z.number().min(0).max(500).default(200),
  }).default({}),
  
  // Vector Store Configuration
  vectorStore: z.object({
    provider: z.enum(['qdrant', 'pinecone', 'chroma', 'weaviate']).default('qdrant'),
    config: z.object({
      host: z.string().default('localhost'),
      port: z.number().default(6333),
      collection: z.string().default('memories'),
      distance: z.enum(['cosine', 'euclidean', 'dot']).default('cosine'),
    }).default({}),
  }).default({}),
  
  // Memory Configuration
  memory: z.object({
    maxMemories: z.number().min(1).max(10000).default(1000),
    retentionDays: z.number().min(1).max(365).default(90),
    autoDelete: z.boolean().default(false),
    similarityThreshold: z.number().min(0).max(1).default(0.7),
    deduplication: z.boolean().default(true),
    categorization: z.object({
      enabled: z.boolean().default(true),
      autoCategory: z.boolean().default(true),
      maxCategories: z.number().min(1).max(100).default(20),
    }).default({}),
  }).default({}),
  
  // Performance Configuration
  performance: z.object({
    batchSize: z.number().min(1).max(100).default(10),
    concurrency: z.number().min(1).max(20).default(5),
    timeout: z.number().min(1000).max(60000).default(30000),
    retryAttempts: z.number().min(0).max(5).default(3),
    caching: z.object({
      enabled: z.boolean().default(true),
      ttl: z.number().min(60).max(86400).default(3600),
      maxSize: z.number().min(10).max(1000).default(100),
    }).default({}),
  }).default({}),
});

const SystemConfigSchema = z.object({
  mem0: Mem0ConfigSchema.default({}),
  
  // MCP Server Configuration
  mcp: z.object({
    maxRequestsPerSession: z.number().min(1).max(10000).default(1000),
    sessionTimeoutHours: z.number().min(1).max(168).default(24),
    enableAuditLogging: z.boolean().default(true),
    securityLogLevel: z.enum(['error', 'warn', 'info', 'debug']).default('warn'),
    rateLimiting: z.object({
      enabled: z.boolean().default(true),
      windowMs: z.number().min(1000).max(3600000).default(900000), // 15 minutes
      maxRequests: z.number().min(1).max(1000).default(100),
    }).default({}),
  }).default({}),
  
  // Web Configuration
  web: z.object({
    enableRegistration: z.boolean().default(true),
    requireEmailVerification: z.boolean().default(false),
    sessionDuration: z.number().min(3600).max(604800).default(86400), // 24 hours
    maxLoginAttempts: z.number().min(1).max(20).default(5),
    lockoutDuration: z.number().min(300).max(86400).default(1800), // 30 minutes
  }).default({}),
}).default({});

class ConfigManager {
  constructor() {
    this.configPath = CONFIG.CONFIG_PATH;
    this.config = null;
    this.envConfig = this.loadEnvironmentConfig();
  }

  /**
   * Load configuration from environment variables
   */
  loadEnvironmentConfig() {
    const env = process.env;
    
    return {
      mem0: {
        apiUrl: env.MEM0_API_URL,
        apiKey: env.MEM0_API_KEY,
        
        llm: {
          provider: env.LLM_PROVIDER || 'openai',
          model: env.LLM_MODEL || 'gpt-3.5-turbo',
          apiKey: env.OPENROUTER_API_KEY || env.OPENAI_API_KEY,
          apiBase: env.OPENROUTER_API_BASE || env.OPENAI_API_BASE,
          temperature: parseFloat(env.LLM_TEMPERATURE || '0.1'),
          maxTokens: parseInt(env.LLM_MAX_TOKENS || '1000'),
          topP: parseFloat(env.LLM_TOP_P || '1'),
          frequencyPenalty: parseFloat(env.LLM_FREQUENCY_PENALTY || '0'),
          presencePenalty: parseFloat(env.LLM_PRESENCE_PENALTY || '0'),
        },
        
        embedder: {
          provider: env.EMBEDDER_PROVIDER || 'openai',
          model: env.EMBEDDING_MODEL || 'text-embedding-3-small',
          apiKey: env.EMBEDDER_API_KEY || env.OPENROUTER_API_KEY || env.OPENAI_API_KEY,
          apiBase: env.EMBEDDER_API_BASE || env.OPENROUTER_API_BASE || env.OPENAI_API_BASE,
          dimensions: env.EMBEDDING_DIMENSIONS ? parseInt(env.EMBEDDING_DIMENSIONS) : undefined,
          chunkSize: parseInt(env.CHUNK_SIZE || '1000'),
          chunkOverlap: parseInt(env.CHUNK_OVERLAP || '200'),
        },
        
        vectorStore: {
          provider: env.VECTOR_STORE_PROVIDER || 'postgres',
          config: {
            host: env.VECTOR_STORE_HOST || 'postgresql',
            port: parseInt(env.VECTOR_STORE_PORT || '5432'),
            database: env.VECTOR_STORE_DATABASE || 'mem0',
            user: env.VECTOR_STORE_USER || 'mem0',
            password: env.VECTOR_STORE_PASSWORD,
            table: env.VECTOR_STORE_TABLE || 'embeddings',
            collection: env.VECTOR_STORE_COLLECTION || 'memories',
            sslMode: env.VECTOR_STORE_SSL_MODE || 'prefer',
          },
        },
        
        vectorStore: {
          provider: env.VECTOR_STORE_PROVIDER || 'qdrant',
          config: {
            host: env.VECTOR_STORE_HOST || 'localhost',
            port: parseInt(env.VECTOR_STORE_PORT || '6333'),
            collection: env.VECTOR_COLLECTION || 'memories',
            distance: env.VECTOR_DISTANCE || 'cosine',
          },
        },
        
        memory: {
          maxMemories: parseInt(env.MAX_MEMORIES_PER_USER || '1000'),
          retentionDays: parseInt(env.MEMORY_RETENTION_DAYS || '90'),
          autoDelete: env.AUTO_DELETE_MEMORIES === 'true',
          similarityThreshold: parseFloat(env.SIMILARITY_THRESHOLD || '0.7'),
          deduplication: env.ENABLE_DEDUPLICATION !== 'false',
          categorization: {
            enabled: env.ENABLE_CATEGORIZATION !== 'false',
            autoCategory: env.AUTO_CATEGORIZATION !== 'false',
            maxCategories: parseInt(env.MAX_CATEGORIES || '20'),
          },
        },
        
        performance: {
          batchSize: parseInt(env.BATCH_SIZE || '10'),
          concurrency: parseInt(env.CONCURRENCY || '5'),
          timeout: parseInt(env.API_TIMEOUT || '30000'),
          retryAttempts: parseInt(env.RETRY_ATTEMPTS || '3'),
          caching: {
            enabled: env.ENABLE_CACHING !== 'false',
            ttl: parseInt(env.CACHE_TTL || '3600'),
            maxSize: parseInt(env.CACHE_MAX_SIZE || '100'),
          },
        },
      },
      
      mcp: {
        maxRequestsPerSession: parseInt(env.MAX_REQUESTS_PER_SESSION || '1000'),
        sessionTimeoutHours: parseInt(env.SESSION_TIMEOUT_HOURS || '24'),
        enableAuditLogging: env.ENABLE_AUDIT_LOGGING !== 'false',
        securityLogLevel: env.SECURITY_LOG_LEVEL || 'warn',
        rateLimiting: {
          enabled: env.ENABLE_RATE_LIMITING !== 'false',
          windowMs: parseInt(env.RATE_LIMIT_WINDOW_MS || '900000'),
          maxRequests: parseInt(env.RATE_LIMIT_MAX_REQUESTS || '100'),
        },
      },
      
      web: {
        enableRegistration: env.ENABLE_REGISTRATION !== 'false',
        requireEmailVerification: env.REQUIRE_EMAIL_VERIFICATION === 'true',
        sessionDuration: parseInt(env.WEB_SESSION_DURATION || '86400'),
        maxLoginAttempts: parseInt(env.MAX_LOGIN_ATTEMPTS || '5'),
        lockoutDuration: parseInt(env.LOCKOUT_DURATION || '1800'),
      },
    };
  }

  /**
   * Load configuration from file and merge with environment
   */
  async loadConfig() {
    try {
      // Load saved configuration
      let savedConfig = {};
      try {
        const configData = await fs.readFile(this.configPath, 'utf8');
        savedConfig = JSON.parse(configData);
      } catch (error) {
        if (error.code !== 'ENOENT') {
          console.warn('Failed to load saved config:', error.message);
        }
      }

      // Merge configurations: environment > saved > defaults
      const mergedConfig = this.deepMerge(
        SystemConfigSchema.parse({}), // defaults
        savedConfig,
        this.removeUndefined(this.envConfig) // environment takes precedence
      );

      // Validate final configuration
      this.config = SystemConfigSchema.parse(mergedConfig);
      console.log('Configuration loaded successfully');
      
      return this.config;
    } catch (error) {
      console.error('Configuration validation failed:', error);
      throw new Error(`Configuration error: ${error.message}`);
    }
  }

  /**
   * Save configuration to file
   */
  async saveConfig(newConfig) {
    try {
      // Validate configuration
      const validatedConfig = SystemConfigSchema.parse(newConfig);
      
      // Don't save environment-controlled values
      const configToSave = this.removeEnvironmentControlled(validatedConfig);
      
      // Ensure config directory exists
      await fs.mkdir(path.dirname(this.configPath), { recursive: true });
      
      // Save configuration
      await fs.writeFile(this.configPath, JSON.stringify(configToSave, null, 2));
      
      // Update current config (merge with environment again)
      this.config = SystemConfigSchema.parse(
        this.deepMerge(configToSave, this.removeUndefined(this.envConfig))
      );
      
      console.log('Configuration saved successfully');
      return this.config;
    } catch (error) {
      console.error('Failed to save configuration:', error);
      throw new Error(`Failed to save configuration: ${error.message}`);
    }
  }

  /**
   * Get current configuration
   */
  async getConfig() {
    if (!this.config) {
      await this.loadConfig();
    }
    return this.config;
  }

  /**
   * Get mem0 configuration for API client
   */
  async getMem0Config() {
    const config = await this.getConfig();
    return config.mem0;
  }

  /**
   * Update specific configuration section
   */
  async updateConfig(section, updates) {
    const currentConfig = await this.getConfig();
    const newConfig = {
      ...currentConfig,
      [section]: {
        ...currentConfig[section],
        ...updates,
      },
    };
    
    return this.saveConfig(newConfig);
  }

  /**
   * Get configuration schema for UI generation
   */
  getConfigSchema() {
    return CONFIG_SCHEMA;
  }

  /**
   * Remove undefined values from object
   */
  removeUndefined(obj) {
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      if (value !== undefined) {
        if (typeof value === 'object' && value !== null) {
          const nested = this.removeUndefined(value);
          if (Object.keys(nested).length > 0) {
            result[key] = nested;
          }
        } else {
          result[key] = value;
        }
      }
    }
    return result;
  }

  /**
   * Remove environment-controlled values from config
   */
  removeEnvironmentControlled(config) {
    const result = JSON.parse(JSON.stringify(config));
    
    // Remove values that are controlled by environment variables
    const envControlledPaths = [
      'mem0.apiUrl',
      'mem0.apiKey',
      'mem0.llm.provider',
      'mem0.llm.model',
      'mem0.llm.apiKey',
      'mem0.llm.apiBase',
      'mem0.embedder.model',
    ];
    
    envControlledPaths.forEach(path => {
      if (this.hasEnvVariable(path)) {
        this.deletePath(result, path);
      }
    });
    
    return result;
  }

  /**
   * Check if environment variable exists for path
   */
  hasEnvVariable(path) {
    const envVars = ENV_MAPPINGS[path];
    if (!envVars) return false;
    
    if (Array.isArray(envVars)) {
      return envVars.some(env => process.env[env]);
    }
    return !!process.env[envVars];
  }

  /**
   * Delete path from object
   */
  deletePath(obj, path) {
    const keys = path.split('.');
    let current = obj;
    
    for (let i = 0; i < keys.length - 1; i++) {
      if (!current[keys[i]]) return;
      current = current[keys[i]];
    }
    
    delete current[keys[keys.length - 1]];
  }

  /**
   * Deep merge objects
   */
  deepMerge(target, ...sources) {
    if (!sources.length) return target;
    const source = sources.shift();

    if (this.isObject(target) && this.isObject(source)) {
      for (const key in source) {
        if (this.isObject(source[key])) {
          if (!target[key]) Object.assign(target, { [key]: {} });
          this.deepMerge(target[key], source[key]);
        } else {
          Object.assign(target, { [key]: source[key] });
        }
      }
    }

    return this.deepMerge(target, ...sources);
  }

  /**
   * Check if value is object
   */
  isObject(item) {
    return item && typeof item === 'object' && !Array.isArray(item);
  }
}

export default ConfigManager;
