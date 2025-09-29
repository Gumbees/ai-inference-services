import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy as OpenIDConnectStrategy } from 'passport-openidconnect';
import { Strategy as LocalStrategy } from 'passport-local';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import { createClient } from 'redis';
import ConnectRedis from 'connect-redis';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { fileURLToPath } from 'url';

// Import our organized constants and services
import { CONFIG, SUCCESS_MESSAGES, ERROR_MESSAGES } from './constants.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Web Configuration Server for Gumbees MCP Server
 * Provides OAuth/OpenID authentication and configuration management
 */

class WebConfigServer {
  constructor(authService, mem0Service, configManager) {
    this.app = express();
    this.authService = authService;
    this.mem0Service = mem0Service;
    this.configManager = configManager;
    
    // Use centralized configuration
    this.config = {
      port: CONFIG.WEB_PORT,
      sessionSecret: CONFIG.SESSION_SECRET,
      baseUrl: CONFIG.BASE_URL,
      oauth: CONFIG.OAUTH,
      redis: CONFIG.REDIS,
    };

    this.setupMiddleware();
    this.setupAuthentication();
    this.setupRoutes();
  }

  async setupMiddleware() {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
          scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
    }));

    // CORS
    this.app.use(cors({
      origin: CONFIG.ALLOWED_ORIGINS.length > 0 ? CONFIG.ALLOWED_ORIGINS : [this.config.baseUrl],
      credentials: true,
    }));

    // Logging
    this.app.use(morgan('combined'));

    // Body parsing
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));

    // Session management
    let sessionStore;
    if (this.config.redis.enabled) {
      try {
        const redisClient = createClient({ url: this.config.redis.url });
        await redisClient.connect();
        sessionStore = new ConnectRedis({ client: redisClient });
        console.log('Connected to Redis for session storage');
      } catch (error) {
        console.warn('Redis connection failed, using memory store:', error.message);
      }
    }

    this.app.use(session({
      store: sessionStore,
      secret: this.config.sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
      },
    }));

    // Passport initialization
    this.app.use(passport.initialize());
    this.app.use(passport.session());

    // Static files
    this.app.use('/static', express.static(path.join(__dirname, 'public')));
  }

  setupAuthentication() {
    // Passport serialization
    passport.serializeUser((user, done) => {
      done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
      try {
        const user = this.authService.getUserById(id);
        done(null, user);
      } catch (error) {
        done(error, null);
      }
    });

    // Local strategy (fallback)
    passport.use(new LocalStrategy(
      async (username, password, done) => {
        try {
          const result = await this.authService.login(username, password);
          done(null, result);
        } catch (error) {
          done(null, false, { message: error.message });
        }
      }
    ));

    // OpenID Connect strategy (Authentik)
    if (this.config.oauth.enabled && this.config.oauth.issuer) {
      passport.use(new OpenIDConnectStrategy({
        issuer: this.config.oauth.issuer,
        clientID: this.config.oauth.clientID,
        clientSecret: this.config.oauth.clientSecret,
        callbackURL: `${this.config.baseUrl}${this.config.oauth.callbackURL}`,
        scope: this.config.oauth.scope,
      }, async (issuer, profile, done) => {
        try {
          // Extract user info from OAuth profile
          const userInfo = {
            id: profile.id,
            username: profile.username || profile.preferred_username || profile.email,
            email: profile.email,
            name: profile.name || profile.displayName,
            provider: 'oauth',
            providerId: profile.id,
            profile: profile,
          };

          // Create or update user in your system
          const user = await this.authService.findOrCreateOAuthUser(userInfo);
          
          done(null, user);
        } catch (error) {
          done(error, null);
        }
      }));
    }
  }

  setupRoutes() {
    // Home page
    this.app.get('/', this.requireAuth, (req, res) => {
      res.send(this.renderDashboard(req.user));
    });

    // Login page
    this.app.get('/login', (req, res) => {
      if (req.isAuthenticated()) {
        return res.redirect('/');
      }
      res.send(this.renderLogin());
    });

    // Local login
    this.app.post('/auth/local', passport.authenticate('local', {
      successRedirect: '/',
      failureRedirect: '/login?error=1',
    }));

    // OAuth login
    if (this.config.oauth.enabled) {
      this.app.get('/auth/oauth', passport.authenticate('openidconnect'));
      
      this.app.get('/auth/callback', 
        passport.authenticate('openidconnect', {
          successRedirect: '/',
          failureRedirect: '/login?error=oauth',
        })
      );
    }

    // Logout
    this.app.post('/logout', (req, res) => {
      req.logout((err) => {
        if (err) {
          console.error('Logout error:', err);
        }
        res.redirect('/login');
      });
    });

    // API Routes
    this.app.get('/api/user', this.requireAuth, (req, res) => {
      res.json({
        id: req.user.id,
        username: req.user.username,
        email: req.user.email,
        name: req.user.name,
      });
    });

    // Generate MCP token for authenticated user
    this.app.post('/api/mcp-token', this.requireAuth, (req, res) => {
      try {
        const token = this.authService.generateMCPToken(
          req.user.id,
          req.user.username,
          '30d'
        );
        
        res.json({ 
          token,
          userId: req.user.id,
          expiresIn: '30 days'
        });
      } catch (error) {
        res.status(500).json({ error: 'Failed to generate token' });
      }
    });

    // Memory statistics
    this.app.get('/api/memories/stats', this.requireAuth, async (req, res) => {
      try {
        const stats = await this.mem0Service.getMemoryStats(req.user.id);
        res.json(stats);
      } catch (error) {
        res.status(500).json({ error: 'Failed to fetch memory statistics' });
      }
    });

    // Memory management
    this.app.get('/api/memories', this.requireAuth, async (req, res) => {
      try {
        const limit = parseInt(req.query.limit) || 50;
        const category = req.query.category;
        
        let memories = await this.mem0Service.getMemories(req.user.id, limit);
        
        if (category && category !== 'all') {
          memories = memories.filter(m => m.metadata?.category === category);
        }
        
        res.json(memories);
      } catch (error) {
        res.status(500).json({ error: 'Failed to fetch memories' });
      }
    });

    this.app.delete('/api/memories/:id', this.requireAuth, async (req, res) => {
      try {
        // Validate ownership and delete
        await this.mem0Service.validateMemoryOwnership(req.params.id, req.user.id);
        await this.mem0Service.deleteMemory(req.params.id);
        res.json({ success: true, message: SUCCESS_MESSAGES.MEMORY_DELETED });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Configuration endpoints
    this.app.get('/api/config', this.requireAuth, async (req, res) => {
      try {
        const config = await this.configManager.getConfig();
        const schema = this.configManager.getConfigSchema();
        
        res.json({
          config,
          schema,
          oauth: {
            enabled: this.config.oauth.enabled,
            issuer: this.config.oauth.issuer,
          },
          environment: {
            mem0_url: process.env.MEM0_API_URL,
            mem0_api_key_set: !!process.env.MEM0_API_KEY,
            llm_provider: process.env.LLM_PROVIDER,
            embedding_model: process.env.EMBEDDING_MODEL,
          },
        });
      } catch (error) {
        res.status(500).json({ error: 'Failed to load configuration' });
      }
    });

    // Get configuration schema for UI generation
    this.app.get('/api/config/schema', this.requireAuth, (req, res) => {
      try {
        const schema = this.configManager.getConfigSchema();
        res.json(schema);
      } catch (error) {
        res.status(500).json({ error: 'Failed to get configuration schema' });
      }
    });

    // Update configuration
    this.app.put('/api/config/:section', this.requireAuth, async (req, res) => {
      try {
        const { section } = req.params;
        const updates = req.body;

        const updatedConfig = await this.configManager.updateConfig(section, updates);
        
        // Log configuration change
        console.log(`Configuration updated by user ${req.user.id}: ${section}`);
        
        res.json({ 
          success: true, 
          message: `${section} ${SUCCESS_MESSAGES.CONFIG_SAVED}`,
          config: updatedConfig 
        });
      } catch (error) {
        console.error('Configuration update failed:', error);
        res.status(400).json({ error: error.message });
      }
    });

    // Test mem0 connection
    this.app.post('/api/config/test-mem0', this.requireAuth, async (req, res) => {
      try {
        const { apiUrl, apiKey } = req.body;
        
        // Create temporary service for testing
        const { Mem0Service } = await import('./services/mem0-service.js');
        const testService = new Mem0Service(apiUrl, apiKey);
        
        // Test connection
        const result = await testService.testConnection();
        
        if (result.success) {
          res.json({ 
            success: true, 
            message: SUCCESS_MESSAGES.CONNECTION_SUCCESSFUL 
          });
        } else {
          res.status(400).json(result);
        }
      } catch (error) {
        console.warn('mem0 connection test failed:', error.message);
        res.status(400).json({ 
          success: false, 
          error: 'Connection failed: ' + error.message 
        });
      }
    });

    // Reset configuration to defaults
    this.app.post('/api/config/reset/:section', this.requireAuth, async (req, res) => {
      try {
        const { section } = req.params;
        
        // Load default configuration
        const defaultConfig = await this.configManager.getConfig();
        
        // Reset specific section
        const resetConfig = {};
        resetConfig[section] = defaultConfig[section];
        
        await this.configManager.saveConfig({
          ...await this.configManager.getConfig(),
          ...resetConfig
        });
        
        console.log(`Configuration reset by user ${req.user.id}: ${section}`);
        
        res.json({ 
          success: true, 
          message: `${section} ${SUCCESS_MESSAGES.CONFIG_RESET}` 
        });
      } catch (error) {
        res.status(400).json({ error: error.message });
      }
    });

    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ status: 'healthy', timestamp: new Date().toISOString() });
    });
  }

  requireAuth = (req, res, next) => {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect('/login');
  };

  renderLogin() {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gumbees MCP Server - Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .login-container { max-width: 400px; margin: 10vh auto; }
        .card { border: none; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .card-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 15px 15px 0 0 !important; }
        .btn-oauth { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); border: none; }
        .divider { text-align: center; margin: 20px 0; position: relative; }
        .divider::before { content: ''; position: absolute; top: 50%; left: 0; right: 0; height: 1px; background: #dee2e6; }
        .divider span { background: white; padding: 0 15px; color: #6c757d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-container">
            <div class="card">
                <div class="card-header text-center py-4">
                    <h2 class="mb-0">🧠 Gumbees MCP</h2>
                    <small>Memory Context Protocol Server</small>
                </div>
                <div class="card-body p-4">
                    ${this.config.oauth.enabled ? `
                    <div class="d-grid mb-3">
                        <a href="/auth/oauth" class="btn btn-oauth btn-lg text-white">
                            🔐 Login with Authentik
                        </a>
                    </div>
                    <div class="divider">
                        <span>or</span>
                    </div>
                    ` : ''}
                    
                    <form method="POST" action="/auth/local">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary btn-lg">Login</button>
                        </div>
                    </form>
                    
                    ${new URLSearchParams(window.location.search).get('error') ? `
                    <div class="alert alert-danger mt-3">
                        Login failed. Please check your credentials.
                    </div>
                    ` : ''}
                </div>
            </div>
        </div>
    </div>
</body>
</html>`;
  }

  renderDashboard(user) {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gumbees MCP Server - Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #f8f9fa; }
        .navbar { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important; }
        .card { border: none; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        .memory-card { border-left: 4px solid #667eea; }
        .token-display { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 10px; font-family: monospace; word-break: break-all; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <span class="navbar-brand">🧠 Gumbees MCP Server</span>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">Welcome, ${user.username}</span>
                <form method="POST" action="/logout" class="d-inline">
                    <button type="submit" class="btn btn-outline-light btn-sm">Logout</button>
                </form>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <!-- Navigation Tabs -->
        <ul class="nav nav-tabs" id="mainTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="dashboard-tab" data-bs-toggle="tab" data-bs-target="#dashboard" type="button" role="tab">
                    🏠 Dashboard
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="config-tab" data-bs-toggle="tab" data-bs-target="#configuration" type="button" role="tab">
                    ⚙️ Configuration
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="memories-tab" data-bs-toggle="tab" data-bs-target="#memories" type="button" role="tab">
                    🧠 Memories
                </button>
            </li>
        </ul>

        <div class="tab-content" id="mainTabContent">
            <!-- Dashboard Tab -->
            <div class="tab-pane fade show active" id="dashboard" role="tabpanel">
                <div class="row mt-4">
                    <div class="col-md-8">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">🎯 MCP Configuration</h5>
                            </div>
                            <div class="card-body">
                                <p>Use this token to authenticate with the MCP server:</p>
                                <div class="mb-3">
                                    <button id="generateToken" class="btn btn-primary">Generate MCP Token</button>
                                </div>
                                <div id="tokenDisplay" style="display: none;">
                                    <label class="form-label">Your MCP Token:</label>
                                    <div class="token-display" id="tokenValue"></div>
                                    <small class="text-muted">Save this token securely. You'll need it to configure your MCP client.</small>
                                </div>
                                
                                <hr>
                                
                                <h6>🔧 Client Configuration Example:</h6>
                                <pre class="bg-light p-3 rounded"><code>{
  "mcpServers": {
    "gumbees-mem0": {
      "command": "docker",
      "args": [
        "exec", "-i", 
        "ai-inference-services-gumbees-mcp-server-1",
        "node", "src/index.js"
      ],
      "env": {
        "MCP_TOKEN": "YOUR_TOKEN_HERE"
      }
    }
  }
}</code></pre>
                            </div>
                        </div>

                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">📊 System Status</h5>
                            </div>
                            <div class="card-body" id="systemStatus">
                                Loading system status...
                            </div>
                        </div>
                    </div>

                    <div class="col-md-4">
                        <div class="card stat-card">
                            <div class="card-body text-center">
                                <h3 id="totalMemories">-</h3>
                                <p class="mb-0">Total Memories</p>
                            </div>
                        </div>

                        <div class="card">
                            <div class="card-header">
                                <h6 class="mb-0">📊 Categories</h6>
                            </div>
                            <div class="card-body">
                                <div id="categoryList">Loading...</div>
                            </div>
                        </div>

                        <div class="card">
                            <div class="card-header">
                                <h6 class="mb-0">ℹ️ Server Info</h6>
                            </div>
                            <div class="card-body">
                                <small class="text-muted">
                                    <strong>User ID:</strong> ${user.id}<br>
                                    <strong>Auth Method:</strong> ${user.provider || 'local'}<br>
                                    <strong>Status:</strong> <span class="text-success">Connected</span>
                                </small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Configuration Tab -->
            <div class="tab-pane fade" id="configuration" role="tabpanel">
                <div class="row mt-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">⚙️ mem0 Configuration</h5>
                                <div>
                                    <button id="testConnection" class="btn btn-outline-primary btn-sm me-2">Test Connection</button>
                                    <button id="resetConfig" class="btn btn-outline-warning btn-sm me-2">Reset to Defaults</button>
                                    <button id="saveConfig" class="btn btn-primary btn-sm">Save Configuration</button>
                                </div>
                            </div>
                            <div class="card-body">
                                <div id="configForm">
                                    Loading configuration...
                                </div>
                                <div id="configStatus" class="mt-3"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Memories Tab -->
            <div class="tab-pane fade" id="memories" role="tabpanel">
                <div class="row mt-4">
                    <div class="col-md-8">
                        <div class="card">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">🧠 Memory Management</h5>
                                <div>
                                    <select id="categoryFilter" class="form-select form-select-sm" style="width: auto;">
                                        <option value="all">All Categories</option>
                                    </select>
                                </div>
                            </div>
                            <div class="card-body">
                                <div id="memoryList">Loading memories...</div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header">
                                <h6 class="mb-0">📈 Memory Statistics</h6>
                            </div>
                            <div class="card-body">
                                <div id="memoryStats">Loading statistics...</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentConfig = {};
        let configSchema = {};

        // Generate MCP Token
        document.getElementById('generateToken').addEventListener('click', async () => {
            try {
                const response = await fetch('/api/mcp-token', { method: 'POST' });
                const data = await response.json();
                document.getElementById('tokenValue').textContent = data.token;
                document.getElementById('tokenDisplay').style.display = 'block';
            } catch (error) {
                alert('Failed to generate token');
            }
        });

        // Load configuration
        async function loadConfiguration() {
            try {
                const response = await fetch('/api/config');
                const data = await response.json();
                currentConfig = data.config;
                configSchema = data.schema;
                renderConfigForm();
                updateSystemStatus(data.environment);
            } catch (error) {
                console.error('Failed to load configuration:', error);
                document.getElementById('configForm').innerHTML = '<div class="alert alert-danger">Failed to load configuration</div>';
            }
        }

        // Render configuration form
        function renderConfigForm() {
            const form = document.getElementById('configForm');
            let html = '';

            if (configSchema.mem0 && configSchema.mem0.sections) {
                configSchema.mem0.sections.forEach(section => {
                    html += \`
                        <div class="mb-4">
                            <h6 class="border-bottom pb-2">\${section.title}</h6>
                            <div class="row">
                    \`;

                    section.fields.forEach(field => {
                        const value = getNestedValue(currentConfig.mem0, field.key);
                        const isEnvControlled = field.envControlled;
                        const disabled = isEnvControlled ? 'disabled' : '';
                        const helpText = isEnvControlled ? '<small class="text-muted">Controlled by environment variable</small>' : '';

                        html += \`
                            <div class="col-md-6 mb-3">
                                <label class="form-label">\${field.label} \${isEnvControlled ? '<span class="badge bg-secondary">ENV</span>' : ''}</label>
                                \${renderField(field, value, disabled)}
                                \${helpText}
                            </div>
                        \`;
                    });

                    html += \`
                            </div>
                        </div>
                    \`;
                });
            }

            form.innerHTML = html;
        }

        // Render individual form field
        function renderField(field, value, disabled) {
            const fieldId = \`config_\${field.key.replace(/\\./g, '_')}\`;
            
            switch (field.type) {
                case 'select':
                    const options = field.options.map(opt => 
                        \`<option value="\${opt}" \${value === opt ? 'selected' : ''}>\${opt}</option>\`
                    ).join('');
                    return \`<select class="form-select" id="\${fieldId}" data-key="\${field.key}" \${disabled}>\${options}</select>\`;
                
                case 'boolean':
                    return \`<div class="form-check">
                        <input class="form-check-input" type="checkbox" id="\${fieldId}" data-key="\${field.key}" \${value ? 'checked' : ''} \${disabled}>
                        <label class="form-check-label" for="\${fieldId}">Enable</label>
                    </div>\`;
                
                case 'number':
                    return \`<input type="number" class="form-control" id="\${fieldId}" data-key="\${field.key}" value="\${value || ''}" 
                        min="\${field.min || ''}" max="\${field.max || ''}" step="\${field.step || '1'}" \${disabled}>>\`;
                
                case 'password':
                    return \`<input type="password" class="form-control" id="\${fieldId}" data-key="\${field.key}" value="\${value || ''}" \${disabled}>>\`;
                
                case 'url':
                    return \`<input type="url" class="form-control" id="\${fieldId}" data-key="\${field.key}" value="\${value || ''}" \${disabled}>>\`;
                
                default:
                    return \`<input type="text" class="form-control" id="\${fieldId}" data-key="\${field.key}" value="\${value || ''}" \${disabled}>>\`;
            }
        }

        // Get nested object value
        function getNestedValue(obj, path) {
            return path.split('.').reduce((current, key) => current?.[key], obj);
        }

        // Set nested object value
        function setNestedValue(obj, path, value) {
            const keys = path.split('.');
            const lastKey = keys.pop();
            const target = keys.reduce((current, key) => {
                if (!current[key]) current[key] = {};
                return current[key];
            }, obj);
            target[lastKey] = value;
        }

        // Save configuration
        document.getElementById('saveConfig').addEventListener('click', async () => {
            try {
                // Collect form data
                const formData = {};
                const inputs = document.querySelectorAll('#configForm [data-key]');
                
                inputs.forEach(input => {
                    if (input.disabled) return; // Skip environment-controlled fields
                    
                    let value;
                    if (input.type === 'checkbox') {
                        value = input.checked;
                    } else if (input.type === 'number') {
                        value = input.value ? parseFloat(input.value) : undefined;
                    } else {
                        value = input.value || undefined;
                    }
                    
                    if (value !== undefined) {
                        setNestedValue(formData, input.dataset.key, value);
                    }
                });

                // Send update
                const response = await fetch('/api/config/mem0', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(formData)
                });

                const result = await response.json();
                
                if (result.success) {
                    document.getElementById('configStatus').innerHTML = 
                        '<div class="alert alert-success">Configuration saved successfully!</div>';
                    currentConfig = result.config;
                    setTimeout(() => {
                        document.getElementById('configStatus').innerHTML = '';
                    }, 3000);
                } else {
                    throw new Error(result.error || 'Failed to save configuration');
                }
            } catch (error) {
                document.getElementById('configStatus').innerHTML = 
                    \`<div class="alert alert-danger">Error: \${error.message}</div>\`;
            }
        });

        // Test connection
        document.getElementById('testConnection').addEventListener('click', async () => {
            try {
                const apiUrl = document.querySelector('[data-key="apiUrl"]')?.value || currentConfig.mem0?.apiUrl;
                const apiKey = document.querySelector('[data-key="apiKey"]')?.value || currentConfig.mem0?.apiKey;

                if (!apiUrl || !apiKey) {
                    alert('Please enter API URL and API Key first');
                    return;
                }

                const response = await fetch('/api/config/test-mem0', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ apiUrl, apiKey })
                });

                const result = await response.json();
                
                if (result.success) {
                    document.getElementById('configStatus').innerHTML = 
                        '<div class="alert alert-success">✅ Connection successful!</div>';
                } else {
                    throw new Error(result.error);
                }
            } catch (error) {
                document.getElementById('configStatus').innerHTML = 
                    \`<div class="alert alert-danger">❌ Connection failed: \${error.message}</div>\`;
            }
        });

        // Reset configuration
        document.getElementById('resetConfig').addEventListener('click', async () => {
            if (!confirm('Are you sure you want to reset the configuration to defaults?')) {
                return;
            }

            try {
                const response = await fetch('/api/config/reset/mem0', { method: 'POST' });
                const result = await response.json();
                
                if (result.success) {
                    document.getElementById('configStatus').innerHTML = 
                        '<div class="alert alert-info">Configuration reset to defaults</div>';
                    await loadConfiguration(); // Reload
                } else {
                    throw new Error(result.error);
                }
            } catch (error) {
                document.getElementById('configStatus').innerHTML = 
                    \`<div class="alert alert-danger">Error: \${error.message}</div>\`;
            }
        });

        // Update system status
        function updateSystemStatus(environment) {
            const status = document.getElementById('systemStatus');
            status.innerHTML = \`
                <div class="row">
                    <div class="col-md-6">
                        <h6>Environment Variables</h6>
                        <ul class="list-unstyled">
                            <li>🔗 mem0 URL: <code>\${environment.mem0_url || 'Not set'}</code></li>
                            <li>🔑 API Key: \${environment.mem0_api_key_set ? '✅ Set' : '❌ Not set'}</li>
                            <li>🤖 LLM Provider: <code>\${environment.llm_provider || 'Default'}</code></li>
                            <li>📊 Embedding Model: <code>\${environment.embedding_model || 'Default'}</code></li>
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <h6>Current Configuration</h6>
                        <ul class="list-unstyled">
                            <li>🔗 API URL: <code>\${currentConfig.mem0?.apiUrl || 'Default'}</code></li>
                            <li>🤖 LLM Model: <code>\${currentConfig.mem0?.llm?.model || 'Default'}</code></li>
                            <li>📊 Embedder: <code>\${currentConfig.mem0?.embedder?.model || 'Default'}</code></li>
                            <li>💾 Max Memories: <code>\${currentConfig.mem0?.memory?.maxMemories || 'Default'}</code></li>
                        </ul>
                    </div>
                </div>
            \`;
        }

        // Load memory statistics and management
        async function loadMemoryManagement() {
            try {
                const response = await fetch('/api/memories/stats');
                const stats = await response.json();
                
                // Update dashboard stats
                document.getElementById('totalMemories').textContent = stats.total;
                
                const categoryHtml = Object.entries(stats.categories)
                    .map(([cat, count]) => \`<div class="d-flex justify-content-between"><span>\${cat}</span><span class="badge bg-primary">\${count}</span></div>\`)
                    .join('');
                document.getElementById('categoryList').innerHTML = categoryHtml || '<em>No categories yet</em>';
                
                // Update memories tab
                updateMemoryStats(stats);
                loadMemoryList();
                updateCategoryFilter(stats.categories);
                
            } catch (error) {
                console.error('Failed to load memory stats:', error);
            }
        }

        // Update memory statistics in memories tab
        function updateMemoryStats(stats) {
            const statsElement = document.getElementById('memoryStats');
            statsElement.innerHTML = \`
                <div class="mb-3">
                    <h4 class="text-primary">\${stats.total}</h4>
                    <small class="text-muted">Total Memories</small>
                </div>
                <div class="mb-3">
                    <h6>Categories</h6>
                    \${Object.entries(stats.categories).map(([cat, count]) => 
                        \`<div class="d-flex justify-content-between mb-1">
                            <span>\${cat}</span>
                            <span class="badge bg-secondary">\${count}</span>
                        </div>\`
                    ).join('')}
                </div>
            \`;
        }

        // Load memory list
        async function loadMemoryList(category = 'all') {
            try {
                const url = category === 'all' ? '/api/memories' : \`/api/memories?category=\${category}\`;
                const response = await fetch(url);
                const memories = await response.json();
                
                const listElement = document.getElementById('memoryList');
                if (memories.length === 0) {
                    listElement.innerHTML = '<div class="text-center text-muted py-4">No memories found</div>';
                    return;
                }
                
                listElement.innerHTML = memories.map(memory => \`
                    <div class="card mb-2">
                        <div class="card-body py-2">
                            <div class="d-flex justify-content-between align-items-start">
                                <div class="flex-grow-1">
                                    <div class="mb-1">\${memory.content || memory.text}</div>
                                    <small class="text-muted">
                                        \${memory.metadata?.category ? \`<span class="badge bg-light text-dark">\${memory.metadata.category}</span>\` : ''}
                                        \${memory.created_at ? new Date(memory.created_at).toLocaleDateString() : ''}
                                    </small>
                                </div>
                                <button class="btn btn-outline-danger btn-sm" onclick="deleteMemory('\${memory.id}')">
                                    🗑️
                                </button>
                            </div>
                        </div>
                    </div>
                \`).join('');
                
            } catch (error) {
                document.getElementById('memoryList').innerHTML = '<div class="alert alert-danger">Failed to load memories</div>';
            }
        }

        // Update category filter
        function updateCategoryFilter(categories) {
            const filter = document.getElementById('categoryFilter');
            const currentValue = filter.value;
            
            filter.innerHTML = '<option value="all">All Categories</option>' +
                Object.keys(categories).map(cat => 
                    \`<option value="\${cat}">\${cat} (\${categories[cat]})</option>\`
                ).join('');
                
            filter.value = currentValue;
        }

        // Delete memory
        async function deleteMemory(memoryId) {
            if (!confirm('Are you sure you want to delete this memory?')) {
                return;
            }
            
            try {
                const response = await fetch(\`/api/memories/\${memoryId}\`, { method: 'DELETE' });
                const result = await response.json();
                
                if (result.success) {
                    await loadMemoryManagement(); // Reload everything
                } else {
                    alert('Failed to delete memory');
                }
            } catch (error) {
                alert('Error deleting memory: ' + error.message);
            }
        }

        // Category filter change
        document.getElementById('categoryFilter').addEventListener('change', (e) => {
            loadMemoryList(e.target.value);
        });

        // Tab change handler
        document.querySelectorAll('#mainTabs button').forEach(tab => {
            tab.addEventListener('shown.bs.tab', (e) => {
                const target = e.target.getAttribute('data-bs-target');
                if (target === '#configuration') {
                    loadConfiguration();
                } else if (target === '#memories') {
                    loadMemoryManagement();
                }
            });
        });

        // Initial load
        loadConfiguration();
        loadMemoryManagement();
    </script>
</body>
</html>`;
  }

  async start() {
    const port = this.config.port;
    this.app.listen(port, () => {
      console.log(`🌐 Web configuration server running on port ${port}`);
      console.log(`📱 Dashboard: http://localhost:${port}`);
      
      if (this.config.oauth.enabled) {
        console.log(`🔐 OAuth enabled with issuer: ${this.config.oauth.issuer}`);
      }
    });
  }
}

export default WebConfigServer;
