#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

// Import our organized services and constants
import { CONFIG, SCHEMAS, ERROR_MESSAGES, SUCCESS_MESSAGES } from './constants.js';
import AuthService from './services/auth-service.js';
import Mem0Service from './services/mem0-service.js';
import ConfigManager from './config-manager.js';
import WebConfigServer from './web-server.js';

/**
 * Gumbees Mem0 MCP Server
 * Provides memory functionality with user authentication
 */

// We'll keep these as simple exports for backward compatibility
// but they now use our new services internally
export { AuthService, Mem0Service };

/**
 * MCP Server Implementation
 */
class GumbeesMem0Server {
  constructor() {
    this.server = new Server(
      {
        name: 'gumbees-mem0-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
          resources: {},
          prompts: {},
        },
      }
    );

    // Initialize services
    this.configManager = new ConfigManager();
    this.authService = new AuthService();
    this.mem0Service = null; // Will be initialized after config loads
    
    this.setupHandlers();
  }

  async initialize() {
    try {
      // Load configuration
      const config = await this.configManager.getConfig();
      
      // Initialize mem0 service with configuration
      this.mem0Service = new Mem0Service(
        config.mem0.apiUrl || CONFIG.MEM0_API_URL,
        config.mem0.apiKey || CONFIG.MEM0_API_KEY
      );

      console.log('MCP Server initialized with configuration');
      
      // Test mem0 connection
      const healthCheck = await this.mem0Service.getServiceHealth();
      if (healthCheck.status === 'healthy') {
        console.log('✅ mem0 service connection verified');
      } else {
        console.warn('⚠️ mem0 service connection issue:', healthCheck.error);
      }
      
    } catch (error) {
      console.error('Failed to initialize MCP Server:', error.message);
      throw error;
    }
  }

  setupHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'register_user',
          description: 'Register a new user account',
          inputSchema: {
            type: 'object',
            properties: {
              username: { type: 'string', description: 'Username (3-50 characters)' },
              password: { type: 'string', description: 'Password (minimum 6 characters)' },
              email: { type: 'string', description: 'Email address (optional)' },
            },
            required: ['username', 'password'],
          },
        },
        {
          name: 'login_user',
          description: 'Login with username and password',
          inputSchema: {
            type: 'object',
            properties: {
              username: { type: 'string', description: 'Username' },
              password: { type: 'string', description: 'Password' },
            },
            required: ['username', 'password'],
          },
        },
        {
          name: 'logout_user',
          description: 'Logout and invalidate session',
          inputSchema: {
            type: 'object',
            properties: {
              session_id: { type: 'string', description: 'Session ID from login' },
            },
            required: ['session_id'],
          },
        },
        {
          name: 'store_memory',
          description: 'Store a memory for the authenticated user',
          inputSchema: {
            type: 'object',
            properties: {
              session_id: { type: 'string', description: 'Session ID from login' },
              content: { type: 'string', description: 'Memory content to store' },
              category: { type: 'string', description: 'Memory category (optional)' },
              metadata: { type: 'object', description: 'Additional metadata (optional)' },
            },
            required: ['session_id', 'content'],
          },
        },
        {
          name: 'search_memories',
          description: 'Search memories for the authenticated user',
          inputSchema: {
            type: 'object',
            properties: {
              session_id: { type: 'string', description: 'Session ID from login' },
              query: { type: 'string', description: 'Search query' },
              limit: { type: 'number', description: 'Maximum results (1-50, default 10)' },
              category: { type: 'string', description: 'Filter by category (optional)' },
            },
            required: ['session_id', 'query'],
          },
        },
        {
          name: 'get_memories',
          description: 'Get all memories for the authenticated user',
          inputSchema: {
            type: 'object',
            properties: {
              session_id: { type: 'string', description: 'Session ID from login' },
              limit: { type: 'number', description: 'Maximum results (default 50)' },
              category: { type: 'string', description: 'Filter by category (optional)' },
            },
            required: ['session_id'],
          },
        },
        {
          name: 'delete_memory',
          description: 'Delete a specific memory',
          inputSchema: {
            type: 'object',
            properties: {
              session_id: { type: 'string', description: 'Session ID from login' },
              memory_id: { type: 'string', description: 'Memory ID to delete' },
            },
            required: ['session_id', 'memory_id'],
          },
        },
      ],
    }));

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'register_user':
            return await this.handleRegisterUser(args);
          case 'login_user':
            return await this.handleLoginUser(args);
          case 'logout_user':
            return await this.handleLogoutUser(args);
          case 'store_memory':
            return await this.handleStoreMemory(args);
          case 'search_memories':
            return await this.handleSearchMemories(args);
          case 'get_memories':
            return await this.handleGetMemories(args);
          case 'delete_memory':
            return await this.handleDeleteMemory(args);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error.message}`,
            },
          ],
          isError: true,
        };
      }
    });

    // List resources
    this.server.setRequestHandler(ListResourcesRequestSchema, async () => ({
      resources: [
        {
          uri: 'mem0://users',
          name: 'User Management',
          description: 'User registration and authentication',
          mimeType: 'application/json',
        },
        {
          uri: 'mem0://memories',
          name: 'Memory Storage',
          description: 'Personal memory storage and retrieval',
          mimeType: 'application/json',
        },
      ],
    }));

    // List available prompts
    this.server.setRequestHandler(ListPromptsRequestSchema, async () => ({
      prompts: [
        {
          name: 'memory_system_guide',
          description: 'Complete guide on how to use the memory system effectively',
        },
        {
          name: 'getting_started',
          description: 'Quick start guide for new users',
        },
        {
          name: 'memory_best_practices',
          description: 'Best practices for storing and organizing memories',
        },
        {
          name: 'search_strategies',
          description: 'How to effectively search through stored memories',
        },
        {
          name: 'authentication_help',
          description: 'Guide for user authentication and session management',
        },
      ],
    }));

    // Handle prompt requests
    this.server.setRequestHandler(GetPromptRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      switch (name) {
        case 'memory_system_guide':
          return this.getMemorySystemGuide(args);
        case 'getting_started':
          return this.getGettingStartedGuide(args);
        case 'memory_best_practices':
          return this.getMemoryBestPractices(args);
        case 'search_strategies':
          return this.getSearchStrategies(args);
        case 'authentication_help':
          return this.getAuthenticationHelp(args);
        default:
          throw new Error(`Unknown prompt: ${name}`);
      }
    });
  }

  // Authentication handlers
  async handleRegisterUser(args) {
    const validation = SCHEMAS.User.safeParse(args);
    if (!validation.success) {
      throw new Error(`Invalid input: ${validation.error.message}`);
    }

    const { username, password, email } = validation.data;
    const result = await this.authService.register(username, password, email);

    return {
      content: [
        {
          type: 'text',
          text: `${SUCCESS_MESSAGES.USER_REGISTERED} User ID: ${result.userId}`,
        },
      ],
    };
  }

  async handleLoginUser(args) {
    const { username, password } = args;
    if (!username || !password) {
      throw new Error('Username and password are required');
    }

    const result = await this.authService.login(username, password);

    return {
      content: [
        {
          type: 'text',
          text: `${SUCCESS_MESSAGES.LOGIN_SUCCESSFUL} Session ID: ${result.sessionId}`,
        },
      ],
    };
  }

  async handleLogoutUser(args) {
    const { session_id } = args;
    if (!session_id) {
      throw new Error('Session ID is required');
    }

    const success = this.authService.logout(session_id);
    
    return {
      content: [
        {
          type: 'text',
          text: success ? SUCCESS_MESSAGES.LOGOUT_SUCCESSFUL : 'Session not found',
        },
      ],
    };
  }

  // Memory access validation using new services
  async validateMemoryAccess(sessionId, memoryId = null, operation = 'read') {
    const session = this.authService.validateSession(sessionId);
    
    // If accessing specific memory, verify ownership
    if (memoryId) {
      await this.mem0Service.validateMemoryOwnership(memoryId, session.userId);
    }

    return session;
  }

  async handleStoreMemory(args) {
    const { session_id, content, category, metadata } = args;
    
    // Enhanced security validation
    const session = await this.validateMemoryAccess(session_id, null, 'create');

    const memoryData = {
      content,
      category,
      metadata: { 
        ...metadata, 
        category,
      },
    };

    const validation = SCHEMAS.Memory.safeParse(memoryData);
    if (!validation.success) {
      throw new Error(`Invalid memory data: ${validation.error.message}`);
    }

    // Store memory using the service
    const result = await this.mem0Service.addMemory(
      session.userId,
      content,
      memoryData.metadata
    );

    return {
      content: [
        {
          type: 'text',
          text: `${SUCCESS_MESSAGES.MEMORY_STORED} Memory ID: ${result.id || 'Unknown'}`,
        },
      ],
    };
  }

  async handleSearchMemories(args) {
    const { session_id, query, limit = 10, category } = args;
    
    // Enhanced security validation
    const session = await this.validateMemoryAccess(session_id, null, 'read');

    const searchData = { query, limit, category };
    const validation = SCHEMAS.Search.safeParse(searchData);
    if (!validation.success) {
      throw new Error(`Invalid search parameters: ${validation.error.message}`);
    }

    // Search using the service (includes security verification)
    const memories = await this.mem0Service.searchMemories(
      session.userId,
      query,
      limit
    );

    const formattedMemories = memories.map((memory, index) => 
      `${index + 1}. ${memory.content || memory.text || JSON.stringify(memory)}`
    ).join('\n');

    return {
      content: [
        {
          type: 'text',
          text: memories.length > 0
            ? `Found ${memories.length} memories:\n\n${formattedMemories}`
            : 'No memories found matching your query.',
        },
      ],
    };
  }

  async handleGetMemories(args) {
    const { session_id, limit = 50, category } = args;
    
    // Enhanced security validation
    const session = await this.validateMemoryAccess(session_id, null, 'read');

    // Get memories using the service (includes security verification)
    let memories = await this.mem0Service.getMemories(session.userId, limit);

    // Filter by category if specified
    if (category && category !== 'all') {
      memories = memories.filter(memory => 
        memory.metadata?.category === category
      );
    }

    const formattedMemories = memories.map((memory, index) => 
      `${index + 1}. ${memory.content || memory.text || JSON.stringify(memory)}`
    ).join('\n');

    return {
      content: [
        {
          type: 'text',
          text: memories.length > 0
            ? `Retrieved ${memories.length} memories:\n\n${formattedMemories}`
            : 'No memories found.',
        },
      ],
    };
  }

  async handleDeleteMemory(args) {
    const { session_id, memory_id } = args;

    if (!memory_id) {
      throw new Error('Memory ID is required');
    }

    // CRITICAL: Validate memory ownership before deletion
    const session = await this.validateMemoryAccess(session_id, memory_id, 'delete');

    // Service handles ownership validation and deletion
    await this.mem0Service.deleteMemory(memory_id);

    return {
      content: [
        {
          type: 'text',
          text: SUCCESS_MESSAGES.MEMORY_DELETED,
        },
      ],
    };
  }

  // Prompt Methods
  getMemorySystemGuide(args) {
    return {
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `# Gumbees Memory System Guide

## Overview
You now have access to a powerful memory system that allows you to:
- Store important information from conversations
- Retrieve relevant memories based on context
- Maintain user-specific memory isolation
- Organize memories with categories and metadata

## Authentication Flow
**IMPORTANT**: Before using any memory functions, users must authenticate:

1. **First-time users**: Use \`register_user\` 
2. **Returning users**: Use \`login_user\` to get a session_id
3. **All memory operations**: Require the session_id from login

## Tool Usage Guide

### 🔐 Authentication Tools

**register_user**: Create new user account
- Use when: User mentions they're new or want to create an account
- Required: username, password
- Optional: email
- Example: "I'd like to set up a memory system"

**login_user**: Authenticate existing user
- Use when: User wants to access their memories
- Required: username, password
- Returns: session_id (save this for all subsequent operations)
- Example: "I want to access my saved memories"

**logout_user**: End user session
- Use when: User wants to log out or end session
- Required: session_id

### 🧠 Memory Tools

**store_memory**: Save important information
- Use when: User shares preferences, facts, project details, or anything worth remembering
- Required: session_id, content
- Optional: category (e.g., "preferences", "projects", "facts")
- Example: User says "I prefer React over Vue" → Store this preference

**search_memories**: Find relevant stored memories
- Use when: Current conversation could benefit from past context
- Required: session_id, query
- Optional: limit (default 10), category filter
- Use semantic search - related concepts will be found even with different wording
- Example: User asks about frontend → Search for "frontend frameworks"

**get_memories**: Retrieve all memories for user
- Use when: User wants to review everything stored
- Required: session_id
- Optional: limit, category filter
- Good for: "What do you remember about me?" questions

**delete_memory**: Remove specific memory
- Use when: User wants to remove outdated or incorrect information
- Required: session_id, memory_id
- Get memory_id from search/get results

## When to Use Memory System

### Automatically Store:
- User preferences (tools, languages, frameworks)
- Project information (tech stack, goals, constraints)
- Personal context (role, company, experience level)
- Important facts or decisions
- Workflow preferences
- Learning goals and progress

### Automatically Search:
- When user asks questions that might relate to stored context
- Before making recommendations (check preferences)
- When continuing previous conversations
- When user mentions topics that might have stored context

### Example Conversation Flow:
1. User: "I'm working on a React project"
   → **store_memory**: "User is working on a React project"

2. User: "What state management should I use?"
   → **search_memories**: "React state management"
   → Use found context: "Since you're working with React..."

3. User: "Actually, I prefer Redux"
   → **store_memory**: "User prefers Redux for state management"

## Categories for Organization
- "preferences": User likes/dislikes, tool choices
- "projects": Current work, tech stacks, goals
- "facts": Personal info, company details, constraints
- "learning": Skills being developed, courses, goals
- "workflow": Process preferences, methodologies
- "decisions": Important choices made, reasoning

## Best Practices
1. **Always authenticate first** - Check if user has session_id
2. **Store proactively** - Save important context as it emerges
3. **Search before advising** - Check for relevant memories before recommendations
4. **Use categories** - Help organize and filter memories
5. **Be conversational** - Don't announce every memory operation
6. **Respect privacy** - Only store what's relevant and helpful

Remember: The goal is to provide increasingly personalized and contextual assistance by building up a knowledge base about each user's preferences, projects, and needs.`
          }
        }
      ]
    };
  }

  getGettingStartedGuide(args) {
    return {
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `# Quick Start Guide for Memory System

## For New Users
If this is your first time using the memory system:

1. **Create Account**: "I'd like to set up a memory system"
   → I'll use \`register_user\` to create your account

2. **Start Sharing Context**: Tell me about:
   - What you're working on
   - Your preferred tools/technologies
   - Your role or goals
   → I'll automatically store relevant information

3. **Experience the Memory**: In future conversations, I'll:
   - Remember your preferences
   - Provide contextual recommendations
   - Build on previous discussions

## For Returning Users
If you already have an account:

1. **Login**: "I want to access my memories" or just start chatting
   → I'll prompt for login if needed

2. **Review Memories**: "What do you remember about me?"
   → I'll show you stored information

3. **Continue Building Context**: Keep sharing new information
   → Your memory profile grows over time

## Example Interaction
**You**: "I'm a frontend developer working on a React app"
**AI**: *Stores: "User is a frontend developer working on React app"*
**AI**: "Great! I'll remember that you're working with React..."

**Later conversation**:
**You**: "What's the best way to handle forms?"
**AI**: *Searches memories: "React forms"*
**AI**: "Since you're working with React, I'd recommend..."

The system learns about you automatically - just chat naturally!`
          }
        }
      ]
    };
  }

  getMemoryBestPractices(args) {
    return {
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `# Memory Best Practices

## What to Store
### ✅ Good Memory Content
- **Preferences**: "User prefers TypeScript over JavaScript"
- **Current Projects**: "Working on e-commerce app with Next.js and Stripe"
- **Constraints**: "Must use company's design system"
- **Goals**: "Learning Docker for deployment"
- **Context**: "Frontend developer at startup, 3 years experience"

### ❌ Avoid Storing
- Temporary information (today's weather)
- Sensitive data (passwords, API keys)
- Very specific details that change often
- Redundant information

## Organization Strategies
### Use Meaningful Categories
- **preferences**: Technology choices, methodologies
- **projects**: Current work, tech stacks
- **learning**: Skills being developed
- **constraints**: Limitations, requirements
- **goals**: Objectives, targets

### Add Useful Metadata
\`\`\`json
{
  "category": "preferences",
  "confidence": "high",
  "context": "web development",
  "last_updated": "2024-01-15"
}
\`\`\`

## Search Strategies
### Effective Search Queries
- Use **semantic concepts**: "frontend frameworks" not "React Vue Angular"
- Be **contextual**: "authentication methods" when discussing login
- **Combine topics**: "React state management" for specific technology contexts

### When to Search
- Before making recommendations
- When user asks "What do you think about..."
- When continuing previous conversations
- When user mentions familiar topics

## Memory Maintenance
### Regular Cleanup
- Delete outdated project information
- Update changed preferences
- Remove completed learning goals

### Quality Over Quantity
- Store meaningful, lasting information
- Avoid cluttering with temporary details
- Focus on context that improves future interactions

## Privacy Considerations
- Only store information relevant to assistance
- Respect user boundaries
- Allow easy deletion of unwanted memories
- Be transparent about what's being stored

Remember: Good memory management creates increasingly personalized and helpful interactions!`
          }
        }
      ]
    };
  }

  getSearchStrategies(args) {
    return {
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `# Effective Memory Search Strategies

## Understanding Semantic Search
The memory system uses **semantic search** - it finds related concepts, not just exact word matches.

### Examples:
- Search "frontend" → Finds "React", "Vue", "CSS", "JavaScript"
- Search "deployment" → Finds "Docker", "AWS", "CI/CD", "production"
- Search "database" → Finds "PostgreSQL", "MongoDB", "queries", "schema"

## Search Query Types

### 1. **Topic-Based Searches**
- "web development" - Broad technology context
- "machine learning" - AI/ML related memories
- "project management" - Workflow and process memories

### 2. **Technology-Specific**
- "React hooks" - Specific framework features
- "Python libraries" - Language-specific tools
- "AWS services" - Platform-specific information

### 3. **Contextual Searches**
- "current project" - Active work context
- "learning goals" - Educational objectives
- "team preferences" - Collaborative constraints

## When to Search Memory

### Before Recommendations
\`\`\`
User: "What database should I use?"
1. Search: "database preferences"
2. Search: "current project technology"
3. Provide contextualized recommendation
\`\`\`

### During Problem Solving
\`\`\`
User: "I'm having trouble with authentication"
1. Search: "authentication methods"
2. Search: "current project stack"
3. Provide relevant solution
\`\`\`

### For Continuity
\`\`\`
User: "How's my project coming along?"
1. Search: "current project"
2. Search: "project goals"
3. Provide personalized update
\`\`\`

## Search Result Optimization

### Use Multiple Searches
- Start broad: "web development"
- Get specific: "React state management" 
- Find constraints: "project requirements"

### Filter by Category
- projects: Current work context
- preferences: Technology choices
- learning: Educational context
- constraints: Limitations to consider

### Limit Results Appropriately
- General context: 5-10 results
- Specific lookup: 3-5 results
- Full review: 20-50 results

## Combining Search with Storage
1. **Search first** to understand existing context
2. **Store new information** that emerges
3. **Update** conflicting or outdated memories
4. **Connect** new info to existing memories

## Common Search Patterns

### Project Context
\`\`\`
search_memories(query="current project", limit=5)
search_memories(query="technology stack", limit=5)
\`\`\`

### Preference Lookup
\`\`\`
search_memories(query="preferred tools", category="preferences")
search_memories(query="framework choice", category="preferences")
\`\`\`

### Learning Context
\`\`\`
search_memories(query="learning goals", category="learning")
search_memories(query="skill development", category="learning")
\`\`\`

Remember: Good search strategy makes the difference between generic advice and truly personalized assistance!`
          }
        }
      ]
    };
  }

  getAuthenticationHelp(args) {
    return {
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text: `# Authentication & Session Management Guide

## User Authentication Flow

### New Users
1. **Registration Required First**
   \`\`\`
   Tool: register_user
   Args: {
     "username": "unique_username",
     "password": "secure_password",
     "email": "optional@email.com"
   }
   \`\`\`

2. **Then Login to Get Session**
   \`\`\`
   Tool: login_user
   Args: {
     "username": "unique_username", 
     "password": "secure_password"
   }
   Returns: session_id
   \`\`\`

### Returning Users
1. **Direct Login**
   \`\`\`
   Tool: login_user
   Args: {
     "username": "existing_username",
     "password": "their_password"
   }
   Returns: session_id
   \`\`\`

## Session Management

### Session ID Usage
- **Required for ALL memory operations**
- **Unique per login session**
- **Expires after period of inactivity**
- **Store in conversation context**

### Example Session Flow
\`\`\`
1. User: "I want to save some information"
2. AI: "I'll need you to log in first"
3. User provides credentials
4. AI: login_user → gets session_id
5. AI: "Great! Now I can store information for you"
6. All subsequent memory operations use this session_id
\`\`\`

## Error Handling

### Common Authentication Errors
- **"User not found"**: Use register_user first
- **"Invalid password"**: Check credentials
- **"Invalid session"**: Re-login required
- **"Username exists"**: Choose different username

### Session Timeout
If session expires:
1. User will get "Invalid session" error
2. Prompt for re-authentication
3. Get new session_id
4. Continue with memory operations

## Security Best Practices

### Password Requirements
- Minimum 6 characters
- Recommend strong passwords
- Don't store or log passwords

### Session Security
- Sessions expire automatically
- Each login generates new session
- Logout invalidates session immediately

## Multi-User Support

### User Isolation
- Each user has completely separate memories
- Session_id ensures proper user context
- No cross-user data access

### Concurrent Sessions
- Multiple users can be logged in simultaneously
- Each has unique session_id
- No interference between users

## Troubleshooting Authentication

### User Forgot Credentials
Currently no password reset - user needs to:
1. Create new account with different username
2. Or contact administrator for account recovery

### Session Issues
- Clear any stored session_id
- Prompt for fresh login
- Generate new session

### Web Dashboard Alternative
Users can also:
1. Visit web dashboard (if configured)
2. Login via OAuth (Authentik, etc.)
3. Generate MCP tokens for automated access

## Best Practices for AI Assistants

### Proactive Authentication
- Check for valid session before memory operations
- Prompt for login when needed
- Handle authentication gracefully

### User Experience
- Don't make authentication feel like a barrier
- Explain the benefits of memory system
- Make login process smooth and quick

### Error Recovery
- Clear, helpful error messages
- Guide users through resolution
- Fallback options when possible

Remember: Smooth authentication leads to better user adoption of the memory system!`
          }
        }
      ]
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Gumbees Mem0 MCP Server running on stdio');
  }
}

// Start the servers
async function main() {
  try {
    const mcpServer = new GumbeesMem0Server();
    
    // Initialize configuration and services
    await mcpServer.initialize();
    
    // Start web server if enabled
    if (CONFIG.WEB_ENABLED) {
      const webServer = new WebConfigServer(
        mcpServer.authService, 
        mcpServer.mem0Service, 
        mcpServer.configManager
      );
      await webServer.start();
    }
    
    // Start MCP server
    console.error('🚀 Starting Gumbees Mem0 MCP Server...');
    await mcpServer.run();
    
  } catch (error) {
    console.error('❌ Failed to start MCP Server:', error.message);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error('Server error:', error);
  process.exit(1);
});
