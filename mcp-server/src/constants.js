import { z } from 'zod';

/**
 * Constants and Configuration for Gumbees MCP Server
 * Centralized configuration management
 */

// Environment-based configuration
export const CONFIG = {
  // MCP Server
  MEM0_API_URL: process.env.MEM0_API_URL || 'http://mem0:8080',
  MEM0_API_KEY: process.env.MEM0_API_KEY,
  JWT_SECRET: process.env.JWT_SECRET || 'gumbees-secret-key-change-in-production',
  
  // Web Server
  WEB_PORT: parseInt(process.env.WEB_PORT || '3000'),
  WEB_ENABLED: process.env.WEB_ENABLED !== 'false',
  SESSION_SECRET: process.env.SESSION_SECRET || process.env.JWT_SECRET || 'change-this-secret',
  BASE_URL: process.env.BASE_URL || 'http://localhost:3000',
  
  // OAuth/OpenID Configuration
  OAUTH: {
    enabled: process.env.OAUTH_ENABLED === 'true',
    issuer: process.env.OAUTH_ISSUER,
    clientID: process.env.OAUTH_CLIENT_ID,
    clientSecret: process.env.OAUTH_CLIENT_SECRET,
    scope: process.env.OAUTH_SCOPE || 'openid profile email',
    callbackURL: process.env.OAUTH_CALLBACK_URL || '/auth/callback',
  },
  
  // Redis Configuration
  REDIS: {
    enabled: process.env.REDIS_ENABLED === 'true',
    url: process.env.REDIS_URL || 'redis://localhost:6379',
  },
  
  // Security Configuration
  SECURITY: {
    saltRounds: 10,
    maxRequestsPerSession: parseInt(process.env.MAX_REQUESTS_PER_SESSION || '1000'),
    sessionTimeoutHours: parseInt(process.env.SESSION_TIMEOUT_HOURS || '24'),
    enableAuditLogging: process.env.ENABLE_AUDIT_LOGGING !== 'false',
    securityLogLevel: process.env.SECURITY_LOG_LEVEL || 'warn',
  },
  
  // File paths
  CONFIG_PATH: process.env.CONFIG_PATH || '/app/data/config.json',
  
  // CORS
  ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS?.split(',') || [],
};

// Validation Schemas
export const SCHEMAS = {
  User: z.object({
    username: z.string().min(3).max(50),
    password: z.string().min(6),
    email: z.string().email().optional(),
  }),

  Memory: z.object({
    content: z.string().min(1),
    category: z.string().optional(),
    metadata: z.record(z.any()).optional(),
  }),

  Search: z.object({
    query: z.string().min(1),
    limit: z.number().min(1).max(50).default(10),
    category: z.string().optional(),
  }),
};

// HTTP Status Codes
export const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  INTERNAL_SERVER_ERROR: 500,
};

// Error Messages
export const ERROR_MESSAGES = {
  INVALID_SESSION: 'Invalid or expired session. Please login again.',
  SESSION_VALIDATION_FAILED: 'Session validation failed. Please login again.',
  SECURITY_VIOLATION: 'Security violation detected. Session terminated. Please login again.',
  ACCESS_DENIED: 'Access denied: You can only access your own memories.',
  USER_NOT_FOUND: 'User not found',
  INVALID_PASSWORD: 'Invalid password',
  USERNAME_EXISTS: 'Username already exists',
  MEMORY_NOT_FOUND: 'Memory not found or access denied.',
  INVALID_TOKEN: 'Invalid or expired token',
  CONFIGURATION_ERROR: 'Configuration validation failed',
};

// Success Messages
export const SUCCESS_MESSAGES = {
  USER_REGISTERED: 'User registered successfully!',
  LOGIN_SUCCESSFUL: 'Login successful!',
  LOGOUT_SUCCESSFUL: 'Logout successful',
  MEMORY_STORED: 'Memory stored successfully!',
  MEMORY_DELETED: 'Memory deleted successfully!',
  CONFIG_SAVED: 'Configuration saved successfully!',
  CONFIG_RESET: 'Configuration reset to defaults',
  CONNECTION_SUCCESSFUL: 'Connection successful!',
};

// Default Configuration Values
export const DEFAULT_CONFIG = {
  mem0: {
    llm: {
      provider: 'openai',
      model: 'gpt-3.5-turbo',
      temperature: 0.1,
      maxTokens: 1000,
      topP: 1,
      frequencyPenalty: 0,
      presencePenalty: 0,
    },
    embedder: {
      provider: 'openai',
      model: 'text-embedding-3-small',
      chunkSize: 1000,
      chunkOverlap: 200,
    },
    vectorStore: {
      provider: 'postgres',
      config: {
        host: 'postgresql',
        port: 5432,
        database: 'mem0',
        user: 'mem0',
        table: 'embeddings',
        collection: 'memories',
        distance: 'cosine',
        sslMode: 'prefer',
      },
    },
    memory: {
      maxMemories: 1000,
      retentionDays: 90,
      autoDelete: false,
      similarityThreshold: 0.7,
      deduplication: true,
      categorization: {
        enabled: true,
        autoCategory: true,
        maxCategories: 20,
      },
    },
    performance: {
      batchSize: 10,
      concurrency: 5,
      timeout: 30000,
      retryAttempts: 3,
      caching: {
        enabled: true,
        ttl: 3600,
        maxSize: 100,
      },
    },
  },
  mcp: {
    maxRequestsPerSession: 1000,
    sessionTimeoutHours: 24,
    enableAuditLogging: true,
    securityLogLevel: 'warn',
    rateLimiting: {
      enabled: true,
      windowMs: 900000, // 15 minutes
      maxRequests: 100,
    },
  },
  web: {
    enableRegistration: true,
    requireEmailVerification: false,
    sessionDuration: 86400, // 24 hours
    maxLoginAttempts: 5,
    lockoutDuration: 1800, // 30 minutes
  },
};

// Configuration Schema for UI
export const CONFIG_SCHEMA = {
  mem0: {
    title: 'mem0 Configuration',
    sections: [
      {
        title: 'API Connection',
        fields: [
          { 
            key: 'apiUrl', 
            label: 'API URL', 
            type: 'url', 
            required: true, 
            envControlled: !!process.env.MEM0_API_URL,
            description: 'URL endpoint for mem0 API service'
          },
          { 
            key: 'apiKey', 
            label: 'API Key', 
            type: 'password', 
            required: true, 
            envControlled: !!process.env.MEM0_API_KEY,
            description: 'Authentication key for mem0 API'
          },
        ],
      },
      {
        title: 'Language Model (LLM)',
        fields: [
          { 
            key: 'llm.provider', 
            label: 'Provider', 
            type: 'select', 
            options: ['openai', 'anthropic', 'openrouter', 'ollama', 'azure'], 
            envControlled: !!process.env.LLM_PROVIDER,
            description: 'LLM service provider'
          },
          { 
            key: 'llm.model', 
            label: 'Model', 
            type: 'text', 
            envControlled: !!process.env.LLM_MODEL,
            description: 'Specific model name to use'
          },
          { 
            key: 'llm.apiKey', 
            label: 'API Key', 
            type: 'password', 
            envControlled: !!(process.env.OPENROUTER_API_KEY || process.env.OPENAI_API_KEY),
            description: 'API key for LLM provider'
          },
          { 
            key: 'llm.apiBase', 
            label: 'API Base URL', 
            type: 'url', 
            envControlled: !!(process.env.OPENROUTER_API_BASE || process.env.OPENAI_API_BASE),
            description: 'Base URL for LLM API endpoints'
          },
          { 
            key: 'llm.temperature', 
            label: 'Temperature', 
            type: 'number', 
            min: 0, 
            max: 2, 
            step: 0.1,
            description: 'Controls randomness in model output'
          },
          { 
            key: 'llm.maxTokens', 
            label: 'Max Tokens', 
            type: 'number', 
            min: 1, 
            max: 32000,
            description: 'Maximum tokens to generate'
          },
        ],
      },
      {
        title: 'Embeddings',
        fields: [
          { 
            key: 'embedder.provider', 
            label: 'Provider', 
            type: 'select', 
            options: ['openai', 'huggingface', 'ollama', 'azure'],
            description: 'Embedding service provider'
          },
          { 
            key: 'embedder.model', 
            label: 'Model', 
            type: 'text', 
            envControlled: !!process.env.EMBEDDING_MODEL,
            description: 'Embedding model to use'
          },
          { 
            key: 'embedder.apiKey', 
            label: 'API Key', 
            type: 'password',
            description: 'API key for embedding provider'
          },
          { 
            key: 'embedder.dimensions', 
            label: 'Dimensions', 
            type: 'number', 
            min: 1, 
            max: 3072,
            description: 'Vector embedding dimensions'
          },
          { 
            key: 'embedder.chunkSize', 
            label: 'Chunk Size', 
            type: 'number', 
            min: 100, 
            max: 8000,
            description: 'Text chunk size for processing'
          },
          { 
            key: 'embedder.chunkOverlap', 
            label: 'Chunk Overlap', 
            type: 'number', 
            min: 0, 
            max: 500,
            description: 'Overlap between text chunks'
          },
        ],
      },
      {
        title: 'Vector Store',
        fields: [
          { 
            key: 'vectorStore.provider', 
            label: 'Provider', 
            type: 'select', 
            options: ['postgres', 'qdrant', 'pinecone', 'chroma', 'weaviate'],
            description: 'Vector database provider'
          },
          { 
            key: 'vectorStore.config.host', 
            label: 'Host', 
            type: 'text',
            description: 'Database host (for PostgreSQL/Qdrant)'
          },
          { 
            key: 'vectorStore.config.port', 
            label: 'Port', 
            type: 'number', 
            min: 1, 
            max: 65535,
            description: 'Database port'
          },
          { 
            key: 'vectorStore.config.database', 
            label: 'Database Name', 
            type: 'text',
            description: 'PostgreSQL database name'
          },
          { 
            key: 'vectorStore.config.user', 
            label: 'Username', 
            type: 'text',
            description: 'Database username'
          },
          { 
            key: 'vectorStore.config.password', 
            label: 'Password', 
            type: 'password',
            description: 'Database password'
          },
          { 
            key: 'vectorStore.config.table', 
            label: 'Table Name', 
            type: 'text',
            description: 'PostgreSQL table for embeddings'
          },
          { 
            key: 'vectorStore.config.collection', 
            label: 'Collection Name', 
            type: 'text',
            description: 'Vector collection/index name'
          },
          { 
            key: 'vectorStore.config.distance', 
            label: 'Distance Metric', 
            type: 'select', 
            options: ['cosine', 'euclidean', 'dot'],
            description: 'Vector similarity distance metric'
          },
          { 
            key: 'vectorStore.config.sslMode', 
            label: 'SSL Mode', 
            type: 'select', 
            options: ['disable', 'prefer', 'require'],
            description: 'PostgreSQL SSL connection mode'
          },
        ],
      },
      {
        title: 'Memory Management',
        fields: [
          { 
            key: 'memory.maxMemories', 
            label: 'Max Memories per User', 
            type: 'number', 
            min: 1, 
            max: 10000,
            description: 'Maximum memories allowed per user'
          },
          { 
            key: 'memory.retentionDays', 
            label: 'Retention Days', 
            type: 'number', 
            min: 1, 
            max: 365,
            description: 'Days to retain memories before deletion'
          },
          { 
            key: 'memory.autoDelete', 
            label: 'Auto Delete Old Memories', 
            type: 'boolean',
            description: 'Automatically delete old memories'
          },
          { 
            key: 'memory.similarityThreshold', 
            label: 'Similarity Threshold', 
            type: 'number', 
            min: 0, 
            max: 1, 
            step: 0.1,
            description: 'Minimum similarity for search results'
          },
          { 
            key: 'memory.deduplication', 
            label: 'Enable Deduplication', 
            type: 'boolean',
            description: 'Remove duplicate memories automatically'
          },
          { 
            key: 'memory.categorization.enabled', 
            label: 'Enable Categorization', 
            type: 'boolean',
            description: 'Automatically categorize memories'
          },
          { 
            key: 'memory.categorization.autoCategory', 
            label: 'Auto Categorization', 
            type: 'boolean',
            description: 'AI-powered automatic categorization'
          },
        ],
      },
      {
        title: 'Performance',
        fields: [
          { 
            key: 'performance.batchSize', 
            label: 'Batch Size', 
            type: 'number', 
            min: 1, 
            max: 100,
            description: 'Number of operations to batch together'
          },
          { 
            key: 'performance.concurrency', 
            label: 'Concurrency', 
            type: 'number', 
            min: 1, 
            max: 20,
            description: 'Maximum concurrent operations'
          },
          { 
            key: 'performance.timeout', 
            label: 'Timeout (ms)', 
            type: 'number', 
            min: 1000, 
            max: 60000,
            description: 'Request timeout in milliseconds'
          },
          { 
            key: 'performance.caching.enabled', 
            label: 'Enable Caching', 
            type: 'boolean',
            description: 'Cache responses for better performance'
          },
          { 
            key: 'performance.caching.ttl', 
            label: 'Cache TTL (seconds)', 
            type: 'number', 
            min: 60, 
            max: 86400,
            description: 'Cache time-to-live in seconds'
          },
        ],
      },
    ],
  },
};

// Environment Variable Mappings
export const ENV_MAPPINGS = {
  'mem0.apiUrl': 'MEM0_API_URL',
  'mem0.apiKey': 'MEM0_API_KEY',
  'mem0.llm.provider': 'LLM_PROVIDER',
  'mem0.llm.model': 'LLM_MODEL',
  'mem0.llm.apiKey': ['OPENROUTER_API_KEY', 'OPENAI_API_KEY'],
  'mem0.llm.apiBase': ['OPENROUTER_API_BASE', 'OPENAI_API_BASE'],
  'mem0.embedder.model': 'EMBEDDING_MODEL',
  'mem0.embedder.provider': 'EMBEDDER_PROVIDER',
  'mem0.embedder.dimensions': 'EMBEDDING_DIMENSIONS',
  'mem0.embedder.chunkSize': 'CHUNK_SIZE',
  'mem0.embedder.chunkOverlap': 'CHUNK_OVERLAP',
  'mem0.memory.maxMemories': 'MAX_MEMORIES_PER_USER',
  'mem0.memory.retentionDays': 'MEMORY_RETENTION_DAYS',
  'mem0.memory.autoDelete': 'AUTO_DELETE_MEMORIES',
  'mem0.memory.similarityThreshold': 'SIMILARITY_THRESHOLD',
  'mem0.memory.deduplication': 'ENABLE_DEDUPLICATION',
  'mem0.memory.categorization.enabled': 'ENABLE_CATEGORIZATION',
  'mem0.memory.categorization.autoCategory': 'AUTO_CATEGORIZATION',
  'mem0.vectorStore.provider': 'VECTOR_STORE_PROVIDER',
  'mem0.vectorStore.config.host': 'VECTOR_STORE_HOST',
  'mem0.vectorStore.config.port': 'VECTOR_STORE_PORT',
  'mem0.vectorStore.config.database': 'VECTOR_STORE_DATABASE',
  'mem0.vectorStore.config.user': 'VECTOR_STORE_USER',
  'mem0.vectorStore.config.password': 'VECTOR_STORE_PASSWORD',
  'mem0.vectorStore.config.table': 'VECTOR_STORE_TABLE',
  'mem0.vectorStore.config.collection': 'VECTOR_STORE_COLLECTION',
  'mem0.vectorStore.config.sslMode': 'VECTOR_STORE_SSL_MODE',
};

export default {
  CONFIG,
  SCHEMAS,
  HTTP_STATUS,
  ERROR_MESSAGES,
  SUCCESS_MESSAGES,
  DEFAULT_CONFIG,
  CONFIG_SCHEMA,
  ENV_MAPPINGS,
};
