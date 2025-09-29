# OAuth/OpenID Connect Setup Guide

This guide walks you through setting up OAuth authentication with Authentik (or other OpenID Connect providers) for the Gumbees MCP Server.

## Table of Contents

- [Authentik Configuration](#authentik-configuration)
- [Environment Variables](#environment-variables)
- [Testing the Setup](#testing-the-setup)
- [Troubleshooting](#troubleshooting)
- [Other OAuth Providers](#other-oauth-providers)

## Authentik Configuration

### 1. Create OAuth2/OpenID Provider

1. **Login to Authentik Admin Interface**
   - Navigate to your Authentik instance (e.g., `https://auth.yourdomain.com`)
   - Login with admin credentials

2. **Create a new Provider**
   - Go to **Applications** → **Providers**
   - Click **Create** → **OAuth2/OpenID Provider**
   - Configure the following:

   ```
   Name: Gumbees MCP Server
   Authorization flow: default-authorization-flow (Authorize with username/email/password)
   Client type: Confidential
   Client ID: gumbees-mcp-server (or generate one)
   Client Secret: [Generate a secure secret]
   Redirect URIs/Origins: 
     - https://mcp.yourdomain.com/auth/callback
     - http://localhost:3000/auth/callback (for development)
   Signing Key: authentik Self-signed Certificate
   ```

3. **Advanced Settings**
   ```
   Scopes: openid, profile, email
   Subject mode: Based on User's ID
   Include claims in id_token: Yes
   ```

### 2. Create Application

1. **Create Application**
   - Go to **Applications** → **Applications**
   - Click **Create**
   - Configure:

   ```
   Name: Gumbees MCP Server
   Slug: gumbees-mcp-server
   Provider: [Select the provider created above]
   Launch URL: https://mcp.yourdomain.com
   ```

2. **Set Icon** (Optional)
   - Upload a brain or memory-related icon

### 3. Configure User Access

1. **Create or Assign Users**
   - Go to **Directory** → **Users**
   - Ensure users who should access the MCP server exist
   - Users can be local Authentik users or from LDAP/AD

2. **Set up Groups** (Optional)
   - Create a group for MCP users
   - Assign users to this group
   - Configure application access based on group membership

## Environment Variables

Update your `.env` file with the Authentik configuration:

```bash
# OAuth/OpenID Connect Configuration
OAUTH_ENABLED=true
OAUTH_ISSUER=https://auth.yourdomain.com/application/o/gumbees-mcp-server/
OAUTH_CLIENT_ID=your-client-id-from-authentik
OAUTH_CLIENT_SECRET=your-client-secret-from-authentik
OAUTH_SCOPE=openid profile email
OAUTH_CALLBACK_URL=/auth/callback

# Web Configuration
MCP_PUBLIC_DOMAIN=mcp.yourdomain.com
MCP_BASE_URL=https://mcp.yourdomain.com
ALLOWED_ORIGINS=https://mcp.yourdomain.com,https://auth.yourdomain.com

# Security
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
SESSION_SECRET=different-session-secret-change-this-too
```

### Finding Your OAuth Issuer URL

The issuer URL follows this pattern for Authentik:
```
https://[your-authentik-domain]/application/o/[application-slug]/
```

For example:
- Authentik domain: `auth.yourdomain.com`
- Application slug: `gumbees-mcp-server`
- Issuer URL: `https://auth.yourdomain.com/application/o/gumbees-mcp-server/`

## Testing the Setup

### 1. Start the Services

```bash
# Build and start all services
docker-compose up -d

# Check logs
docker-compose logs -f gumbees-mcp-server
```

### 2. Test Web Interface

1. **Access the web interface**
   - Local: `http://localhost:3000`
   - Production: `https://mcp.yourdomain.com`

2. **Test OAuth Login**
   - Click "Login with Authentik"
   - Should redirect to Authentik login
   - After authentication, should redirect back to dashboard

3. **Test Local Login** (Fallback)
   - Use the username/password form
   - This works for users created through the MCP interface

### 3. Generate MCP Token

1. **Login via OAuth**
2. **Navigate to Dashboard**
3. **Click "Generate MCP Token"**
4. **Copy the token** for use in MCP client configuration

## Troubleshooting

### Common Issues

#### 1. **Redirect URI Mismatch**
```
Error: redirect_uri_mismatch
```
**Solution:** Ensure the redirect URI in Authentik exactly matches your callback URL:
- Authentik: `https://mcp.yourdomain.com/auth/callback`
- Environment: `OAUTH_CALLBACK_URL=/auth/callback`
- Base URL: `MCP_BASE_URL=https://mcp.yourdomain.com`

#### 2. **Invalid Client**
```
Error: invalid_client
```
**Solution:** Check your client ID and secret:
- Ensure `OAUTH_CLIENT_ID` matches the one in Authentik
- Ensure `OAUTH_CLIENT_SECRET` is correct
- Verify the client type is set to "Confidential"

#### 3. **CORS Issues**
```
Error: CORS policy blocked
```
**Solution:** Update allowed origins:
```bash
ALLOWED_ORIGINS=https://mcp.yourdomain.com,https://auth.yourdomain.com
```

#### 4. **Session Issues**
```
Error: Session store disconnected
```
**Solution:** Check Redis connection:
```bash
# Enable Redis
REDIS_ENABLED=true
REDIS_URL=redis://redis:6379

# Or disable Redis (use memory store)
REDIS_ENABLED=false
```

### Debug Mode

Enable debug logging:
```bash
# Add to docker-compose environment
- DEBUG=passport*,express-session
- NODE_ENV=development
```

### Check OAuth Discovery

Verify Authentik's OpenID configuration:
```bash
curl https://auth.yourdomain.com/application/o/gumbees-mcp-server/.well-known/openid_configuration
```

Should return JSON with endpoints for authorization, token, userinfo, etc.

## Other OAuth Providers

### Google OAuth

```bash
OAUTH_ISSUER=https://accounts.google.com
OAUTH_CLIENT_ID=your-google-client-id
OAUTH_CLIENT_SECRET=your-google-client-secret
```

### Microsoft Azure AD

```bash
OAUTH_ISSUER=https://login.microsoftonline.com/[tenant-id]/v2.0
OAUTH_CLIENT_ID=your-azure-client-id
OAUTH_CLIENT_SECRET=your-azure-client-secret
```

### Keycloak

```bash
OAUTH_ISSUER=https://keycloak.yourdomain.com/auth/realms/[realm-name]
OAUTH_CLIENT_ID=your-keycloak-client-id
OAUTH_CLIENT_SECRET=your-keycloak-client-secret
```

### GitHub OAuth

```bash
OAUTH_ISSUER=https://github.com
OAUTH_CLIENT_ID=your-github-client-id
OAUTH_CLIENT_SECRET=your-github-client-secret
OAUTH_SCOPE=user:email
```

## MCP Client Configuration

### Claude Desktop

Once you have your MCP token, configure Claude Desktop:

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
        "MCP_TOKEN": "your-generated-token-here"
      }
    }
  }
}
```

### Cline

Configure Cline to use the MCP server with your token.

## Security Considerations

### Production Checklist

- [ ] Use HTTPS for all endpoints
- [ ] Set strong JWT and session secrets
- [ ] Configure proper CORS origins
- [ ] Enable Redis for session storage
- [ ] Set up proper SSL certificates
- [ ] Configure rate limiting
- [ ] Enable audit logging
- [ ] Restrict OAuth scopes to minimum required
- [ ] Regular token rotation
- [ ] Monitor failed authentication attempts

### Network Security

```yaml
# docker-compose.yml security additions
networks:
  ai-app:
    driver: bridge
    internal: false  # Set to true for internal-only networks
```

## Support

For issues with this setup:

1. Check the container logs: `docker-compose logs gumbees-mcp-server`
2. Verify environment variables are set correctly
3. Test OAuth endpoints manually
4. Check Authentik logs for authentication issues
5. Verify network connectivity between services

## License

This configuration is part of the Gumbees MCP Server project under MIT License.
