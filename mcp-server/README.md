# Gumbees Mem0 MCP Server

A Model Context Protocol (MCP) server that provides memory functionality using mem0 with user authentication support and web-based configuration.

## Features

- 🔐 **Multi-Auth Support**: Local registration + OAuth/OpenID Connect (Authentik, etc.)
- 🌐 **Web Configuration**: Beautiful dashboard for user management and token generation
- 🧠 **Memory Storage**: Store and retrieve personal memories using mem0
- 🔍 **Smart Search**: Semantic search through stored memories
- 👤 **User Isolation**: Each user's memories are completely separate
- 🏷️ **Categorization**: Organize memories with categories and metadata
- 🔒 **Enterprise Security**: JWT tokens, session management, Redis storage
- 📊 **Memory Analytics**: Dashboard with usage statistics and memory management
- 🐳 **Docker Ready**: Full containerized deployment with Traefik support

## Architecture

```
Web Dashboard (React-like UI)
    ↓ HTTPS/OAuth
Gumbees MCP Server (Node.js + Express)
    ↓ MCP Protocol (JSON-RPC over stdio)
AI Client (Claude Desktop/Cline/etc)
    ↓ REST API calls
Mem0 Service (Docker container)
    ↓ Database operations
PostgreSQL (Docker container)
```

## Web Configuration Interface

### Access the Dashboard
- **Local Development**: `http://localhost:3000`
- **Production**: `https://mcp.yourdomain.com`

### Features
- 🔐 **OAuth Login**: Single sign-on with Authentik, Google, Azure AD, etc.
- 🎯 **Token Management**: Generate and manage MCP access tokens
- 📊 **Memory Analytics**: View memory statistics and usage patterns
- 🗂️ **Category Management**: Organize and browse memories by category
- ⚙️ **Configuration**: Easy setup and testing tools
- 🔍 **Memory Browser**: Search and manage stored memories

### Quick Setup
1. **Configure OAuth** (see [OAUTH_SETUP.md](./OAUTH_SETUP.md))
2. **Start Services**: `docker-compose up -d`
3. **Access Dashboard**: Navigate to your configured domain
4. **Login**: Use OAuth or create local account
5. **Generate Token**: Click "Generate MCP Token" for client configuration

## Available Tools

### Authentication Tools

#### `register_user`
Register a new user account.
```json
{
  "username": "john_doe",
  "password": "secure_password",
  "email": "john@example.com"
}
```

#### `login_user`
Login with username and password.
```json
{
  "username": "john_doe",
  "password": "secure_password"
}
```
Returns a session ID for subsequent requests.

#### `logout_user`
Logout and invalidate session.
```json
{
  "session_id": "your-session-id"
}
```

### Memory Tools

#### `store_memory`
Store a memory for the authenticated user.
```json
{
  "session_id": "your-session-id",
  "content": "I prefer React over Vue for frontend development",
  "category": "preferences",
  "metadata": {
    "topic": "frontend",
    "confidence": "high"
  }
}
```

#### `search_memories`
Search memories using semantic search.
```json
{
  "session_id": "your-session-id",
  "query": "frontend frameworks",
  "limit": 10,
  "category": "preferences"
}
```

#### `get_memories`
Get all memories for the authenticated user.
```json
{
  "session_id": "your-session-id",
  "limit": 50,
  "category": "preferences"
}
```

#### `delete_memory`
Delete a specific memory by ID.
```json
{
  "session_id": "your-session-id",
  "memory_id": "memory-uuid"
}
```

## Usage Examples

### Basic Workflow

1. **Register a new user**:
   ```
   Tool: register_user
   Args: {"username": "alice", "password": "secure123", "email": "alice@example.com"}
   ```

2. **Login to get session**:
   ```
   Tool: login_user
   Args: {"username": "alice", "password": "secure123"}
   Response: Session ID: abc-123-def
   ```

3. **Store some memories**:
   ```
   Tool: store_memory
   Args: {
     "session_id": "abc-123-def",
     "content": "I'm working on a React TypeScript project with Next.js",
     "category": "projects"
   }
   ```

4. **Search memories later**:
   ```
   Tool: search_memories
   Args: {
     "session_id": "abc-123-def", 
     "query": "React project",
     "limit": 5
   }
   ```

### Client Configuration

#### Claude Desktop
Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "gumbees-mem0": {
      "command": "docker",
      "args": [
        "exec", "-i", 
        "ai-inference-services-gumbees-mcp-server-1",
        "node", "src/index.js"
      ],
      "env": {
        "MCP_TOKEN": "your-token-from-web-dashboard"
      }
    }
  }
}
```

**Get your token from the web dashboard:**
1. Login to `https://mcp.yourdomain.com`
2. Click "Generate MCP Token"
3. Copy the token to your Claude Desktop config

#### Cline
Configure Cline to use the MCP server with your dashboard-generated token.

## Security Features

- **Password Hashing**: Uses bcrypt with salt rounds
- **JWT Tokens**: Secure session management with expiration
- **User Isolation**: Complete separation of user data
- **Input Validation**: Zod schema validation for all inputs
- **Session Management**: Automatic session cleanup

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MEM0_API_URL` | URL to mem0 service | `http://mem0:8080` |
| `JWT_SECRET` | Secret key for JWT tokens | `gumbees-secret-key-change-in-production` |
| `NODE_ENV` | Environment mode | `production` |

## Development

### Local Development
```bash
cd mcp-server
npm install
npm run dev
```

### Docker Development
```bash
docker-compose up -d gumbees-mcp-server
docker-compose logs -f gumbees-mcp-server
```

### Testing Tools
You can test the MCP server using the MCP inspector or by connecting it to compatible AI clients.

## Production Considerations

1. **Change JWT Secret**: Always use a strong, unique JWT secret in production
2. **User Persistence**: Current implementation uses in-memory storage for users - consider adding database persistence
3. **Rate Limiting**: Add rate limiting for API endpoints
4. **Monitoring**: Add logging and monitoring for production use
5. **SSL/TLS**: Ensure secure connections in production

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure mem0 service is running and accessible
2. **Authentication Errors**: Check JWT secret configuration
3. **Memory Not Found**: Verify user session and memory ownership

### Logs
```bash
docker-compose logs gumbees-mcp-server
```

## API Reference

The server implements the MCP protocol specification and communicates with mem0's REST API. All memory operations are scoped to the authenticated user's session.

## License

MIT License - see LICENSE file for details.
