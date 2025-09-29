# Security Guide - AI Inference Services

This document outlines the security architecture and best practices for the AI Inference Services platform, with special focus on the Gumbees MCP Server and memory system.

## Table of Contents

- [Security Architecture](#security-architecture)
- [Authentication & Authorization](#authentication--authorization)
- [Data Protection](#data-protection)
- [Network Security](#network-security)
- [API Security](#api-security)
- [Security Configuration](#security-configuration)
- [Monitoring & Auditing](#monitoring--auditing)
- [Incident Response](#incident-response)
- [Security Checklist](#security-checklist)

## Security Architecture

### Multi-Layer Security Model

```
┌─────────────────────────────────────────────────────────┐
│                    External Access                      │
├─────────────────────────────────────────────────────────┤
│ Traefik Proxy + SSL/TLS + Rate Limiting               │
├─────────────────────────────────────────────────────────┤
│ Web Authentication (OAuth/OIDC + Local)                │
├─────────────────────────────────────────────────────────┤
│ MCP Server (JWT + Session Validation)                  │
├─────────────────────────────────────────────────────────┤
│ Memory API (API Key + User Isolation)                  │
├─────────────────────────────────────────────────────────┤
│ Database Layer (PostgreSQL + Encryption)               │
└─────────────────────────────────────────────────────────┘
```

### Security Zones

#### **Public Zone**
- Traefik reverse proxy
- SSL termination
- Rate limiting
- DDoS protection

#### **Application Zone**
- MCP Server
- Web Dashboard
- Authentication services
- Session management

#### **Data Zone**
- mem0 API
- PostgreSQL database
- Redis session store
- Memory storage

#### **Internal Zone**
- Service-to-service communication
- Internal APIs
- Configuration management

## Authentication & Authorization

### Web Authentication

#### OAuth/OpenID Connect (Primary)
- **Authentik Integration**: Enterprise SSO
- **Multiple Providers**: Google, Azure AD, GitHub
- **Standard Flow**: Authorization code with PKCE
- **Session Management**: Redis-backed sessions
- **Token Validation**: JWT with signature verification

#### Local Authentication (Fallback)
- **bcrypt Hashing**: Password security with salt rounds
- **Password Policy**: Minimum 6 characters (configurable)
- **Account Lockout**: Rate limiting on failed attempts
- **Session Timeout**: Configurable session expiration

### MCP Authentication

#### Session-Based Security
```javascript
// Authentication Flow
1. User registers/logs in → Gets session_id
2. All MCP operations require session_id
3. Session validated against JWT token
4. User isolation enforced on all operations
```

#### Security Validations
- **Session Integrity**: JWT token matches session user
- **Ownership Verification**: Memory access validates ownership
- **Cross-User Protection**: Filters prevent data leakage
- **Anomaly Detection**: Suspicious activity monitoring

### API Key Security

#### mem0 API Protection
- **Bearer Token Authentication**: API key required for all requests
- **Service-to-Service**: MCP server authenticates to mem0
- **Key Rotation**: Configurable API key updates
- **Access Logging**: All API requests audited

## Data Protection

### User Data Isolation

#### Memory Segregation
- **User ID Binding**: All memories tagged with user_id
- **Access Control**: Users can only access own memories
- **Query Filtering**: Results filtered by ownership
- **Delete Protection**: Ownership verified before deletion

#### Database Security
- **Encrypted Connections**: TLS for all database traffic
- **User Isolation**: PostgreSQL user permissions
- **Backup Encryption**: Encrypted database backups
- **Data Retention**: Configurable retention policies

### Sensitive Data Handling

#### What's Stored
```
✅ Safe to Store:
- User preferences and settings
- Project context and tech stacks
- Learning goals and progress
- General conversation context

❌ Never Store:
- Passwords or API keys
- Personal identification numbers
- Financial information
- Health/medical data
- Biometric data
```

#### Data Classification
- **Public**: Non-sensitive preferences
- **Internal**: Project and work context
- **Confidential**: Personal details and goals
- **Restricted**: No sensitive data stored

## Network Security

### Container Network Isolation

#### Network Segmentation
```yaml
networks:
  ai-app:          # Internal application communication
  traefik_public:  # External access through proxy
  # PostgreSQL only accessible from ai-app network
  # Redis only accessible from ai-app network
```

#### Service Communication
- **Internal DNS**: Services communicate via container names
- **No External Database Access**: PostgreSQL not exposed externally
- **API Gateway Pattern**: All external access through Traefik
- **TLS Everywhere**: Encrypted communication between services

### External Access Control

#### Traefik Security
- **SSL/TLS Termination**: Let's Encrypt certificates
- **HTTP Security Headers**: HSTS, CSP, X-Frame-Options
- **Rate Limiting**: Per-IP request limits
- **Access Logging**: All requests logged

#### Domain Security
- **HTTPS Only**: HTTP redirects to HTTPS
- **CORS Protection**: Configured allowed origins
- **Subdomain Isolation**: Each service on separate subdomain

## API Security

### mem0 API Protection

#### Authentication Flow
```javascript
MCP Server → mem0 API
Headers: {
  'Authorization': 'Bearer ${MEM0_API_KEY}',
  'X-API-Key': '${MEM0_API_KEY}',
  'Content-Type': 'application/json'
}
```

#### Request Validation
- **API Key Verification**: Every request authenticated
- **User Context**: User ID included in all operations
- **Input Sanitization**: All inputs validated
- **Output Filtering**: Results filtered by ownership

### MCP Protocol Security

#### Tool Call Validation
```javascript
// Every tool call validates:
1. Session exists and is valid
2. JWT token matches session
3. User has permission for operation
4. Input parameters are sanitized
5. Results are filtered by ownership
```

#### Error Handling
- **No Information Leakage**: Generic error messages
- **Security Logging**: Violations logged with details
- **Automatic Cleanup**: Invalid sessions terminated
- **Rate Limiting**: Per-session request limits

## Security Configuration

### Environment Variables

#### Critical Security Settings
```bash
# Authentication
JWT_SECRET=your-super-secret-jwt-key-change-in-production
SESSION_SECRET=different-session-secret-change-this-too
MEM0_API_KEY=gumbees-mem0-secret-key-change-in-production

# Security Features
MAX_REQUESTS_PER_SESSION=1000
SESSION_TIMEOUT_HOURS=24
ENABLE_AUDIT_LOGGING=true
SECURITY_LOG_LEVEL=warn

# OAuth Configuration
OAUTH_ENABLED=true
OAUTH_CLIENT_SECRET=your-oauth-client-secret
```

#### Production Hardening
```bash
# Set strong secrets
openssl rand -base64 32  # For JWT_SECRET
openssl rand -base64 32  # For SESSION_SECRET
openssl rand -base64 32  # For MEM0_API_KEY

# Restrict access
ALLOWED_ORIGINS=https://yourdomain.com
NODE_ENV=production
REDIS_ENABLED=true
```

### Docker Security

#### Container Hardening
```dockerfile
# Non-root user
USER mcpserver

# Health checks
HEALTHCHECK --interval=30s --timeout=3s

# Resource limits
deploy:
  resources:
    limits:
      memory: 512M
      cpus: '0.5'
```

#### Network Policies
```yaml
# Restrict container communication
networks:
  ai-app:
    driver: bridge
    internal: false  # Set to true for internal-only
```

## Monitoring & Auditing

### Security Event Logging

#### Logged Events
```javascript
// Authentication Events
- User registration attempts
- Login success/failure
- Session creation/termination
- OAuth authentication flows

// Authorization Events  
- Memory access attempts
- Cross-user access violations
- Session validation failures
- API key authentication failures

// Data Access Events
- Memory creation/deletion
- Search operations
- Data export requests
- Configuration changes
```

#### Log Format
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "WARN",
  "event": "SECURITY_VIOLATION",
  "user_id": "user-123",
  "session_id": "session-456", 
  "violation_type": "CROSS_USER_ACCESS",
  "details": "User attempted to access memory owned by different user",
  "source_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0..."
}
```

### Security Metrics

#### Key Performance Indicators
- **Authentication Success Rate**: Login success vs. failures
- **Session Anomalies**: Unusual session patterns
- **Access Violations**: Cross-user access attempts
- **API Errors**: Authentication/authorization failures
- **Rate Limit Hits**: Potential abuse attempts

#### Alerting Thresholds
```yaml
alerts:
  - name: "High Failed Login Rate"
    condition: "failed_logins > 10 per minute"
    action: "notify security team"
    
  - name: "Cross-User Access Attempt"
    condition: "security_violation_type == CROSS_USER_ACCESS"
    action: "immediate alert + session termination"
    
  - name: "API Authentication Failures"
    condition: "mem0_auth_failures > 5 per minute"
    action: "check API key rotation"
```

## Incident Response

### Security Incident Types

#### Level 1: Authentication Issues
- **Failed login attempts**
- **Session timeouts**
- **OAuth configuration errors**
- **Response**: Monitor and log, no immediate action

#### Level 2: Access Violations
- **Cross-user data access attempts**
- **Invalid session usage**
- **Suspicious activity patterns**
- **Response**: Terminate sessions, log details, investigate

#### Level 3: System Compromise
- **Unauthorized API access**
- **Database intrusion attempts**
- **Container compromise**
- **Response**: Immediate containment, forensics, recovery

### Response Procedures

#### Immediate Actions
1. **Identify Scope**: Affected users and data
2. **Contain Threat**: Isolate compromised components
3. **Preserve Evidence**: Capture logs and system state
4. **Notify Stakeholders**: Security team and management

#### Recovery Steps
1. **Patch Vulnerabilities**: Apply security fixes
2. **Rotate Credentials**: Update all secrets and keys
3. **Verify Integrity**: Check data consistency
4. **Resume Operations**: Gradual service restoration

## Security Checklist

### Deployment Security

#### Pre-Deployment
- [ ] All secrets configured and rotated
- [ ] HTTPS certificates installed and valid
- [ ] Database connections encrypted
- [ ] Container images scanned for vulnerabilities
- [ ] Network segmentation configured
- [ ] Monitoring and alerting active

#### Post-Deployment
- [ ] Authentication flows tested
- [ ] Access controls verified
- [ ] Security logging functional
- [ ] Rate limiting effective
- [ ] Backup and recovery tested
- [ ] Incident response procedures documented

### Operational Security

#### Daily Operations
- [ ] Security logs reviewed
- [ ] Failed authentication events checked
- [ ] System performance monitored
- [ ] Database integrity verified

#### Weekly Operations
- [ ] Access patterns analyzed
- [ ] Security metrics reviewed
- [ ] Container updates applied
- [ ] Backup integrity tested

#### Monthly Operations
- [ ] Security configuration audited
- [ ] Penetration testing performed
- [ ] Incident response procedures tested
- [ ] Staff security training updated

### Emergency Procedures

#### Security Breach Response
1. **Immediate Isolation**: Stop affected services
2. **Evidence Preservation**: Capture system state
3. **Stakeholder Notification**: Alert security team
4. **Forensic Analysis**: Investigate root cause
5. **System Recovery**: Restore secure operations
6. **Post-Incident Review**: Update procedures

#### Data Compromise Response
1. **Scope Assessment**: Identify affected data
2. **User Notification**: Inform impacted users
3. **Credential Rotation**: Reset all authentication
4. **System Hardening**: Apply additional security
5. **Regulatory Compliance**: Meet legal requirements
6. **Monitoring Enhancement**: Improve detection

## Contact Information

### Security Team
- **Security Officer**: security@yourdomain.com
- **Emergency Contact**: +1-XXX-XXX-XXXX
- **Incident Reporting**: incidents@yourdomain.com

### External Resources
- **OWASP Security Guidelines**: https://owasp.org
- **Docker Security Best Practices**: https://docs.docker.com/engine/security/
- **OAuth Security Considerations**: https://datatracker.ietf.org/doc/html/rfc6819

---

**Last Updated**: January 2024  
**Next Review**: March 2024  
**Document Owner**: Security Team
