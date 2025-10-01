# Security Migration Guide

## Overview
This guide helps migrate from the old insecure implementation to the new security-hardened version.

## Breaking Changes

### 1. Environment Variables
**Old**: Hardcoded secrets in source code
**New**: Environment variables required

#### Required Changes:
1. Create `.env` file with required variables (see `env.example`)
2. Remove hardcoded secrets from source code
3. Update deployment scripts to use environment variables

### 2. Authentication Changes
**Old**: Simple JWT with hardcoded secret
**New**: Secure JWT with proper validation

#### Required Changes:
1. Update client to handle new JWT structure
2. Implement refresh token rotation
3. Update token storage on client side

### 3. API Response Changes
**Old**: Detailed error messages with stack traces
**New**: Generic error messages for security

#### Required Changes:
1. Update error handling in client applications
2. Remove dependency on detailed error messages
3. Implement proper error logging on client side

### 4. Input Validation
**Old**: No input validation
**New**: Strict input validation with Joi

#### Required Changes:
1. Update client to send properly formatted data
2. Handle validation error responses
3. Implement client-side validation

## Migration Steps

### Step 1: Environment Setup
```bash
# Copy environment template
cp env.example .env

# Update with your actual values
nano .env
```

### Step 2: Database Migration
```bash
# Backup existing database
mongodump --db merchants --out backup/

# Update existing user passwords (if needed)
# Run password migration script
node scripts/migrate-passwords.js
```

### Step 3: Update Dependencies
```bash
# Install new dependencies
npm install

# Update existing dependencies
npm update
```

### Step 4: Test Migration
```bash
# Run security tests
npm test -- tests/security.test.js

# Run integration tests
npm test

# Check for vulnerabilities
npm audit
```

### Step 5: Deploy
```bash
# Deploy to staging first
npm run deploy:staging

# Test in staging environment
# Deploy to production
npm run deploy:production
```

## Client-Side Changes Required

### 1. Authentication Updates
```javascript
// Old way
const token = localStorage.getItem('token');

// New way
const token = localStorage.getItem('accessToken');
const refreshToken = localStorage.getItem('refreshToken');

// Handle token refresh
if (isTokenExpired(token)) {
  const newToken = await refreshAccessToken(refreshToken);
  localStorage.setItem('accessToken', newToken);
}
```

### 2. Error Handling Updates
```javascript
// Old way
if (error.response.data.error) {
  showError(error.response.data.error);
}

// New way
if (error.response.data.error) {
  // Log detailed error for debugging
  console.error('API Error:', error.response.data);
  
  // Show generic message to user
  showError('An error occurred. Please try again.');
}
```

### 3. Input Validation Updates
```javascript
// Old way
const userData = {
  email: emailInput.value,
  password: passwordInput.value
};

// New way
const userData = {
  email: emailInput.value.trim(),
  password: passwordInput.value
};

// Validate before sending
if (!isValidEmail(userData.email)) {
  showError('Please enter a valid email address');
  return;
}
```

## Rollback Plan

### If Issues Occur:
1. **Immediate Rollback**:
   ```bash
   # Revert to previous version
   git checkout previous-version
   npm install
   npm start
   ```

2. **Database Rollback**:
   ```bash
   # Restore database backup
   mongorestore --db merchants backup/merchants/
   ```

3. **Environment Rollback**:
   ```bash
   # Revert environment variables
   cp .env.backup .env
   ```

## Testing Checklist

### Pre-Migration Testing
- [ ] All existing functionality works
- [ ] No breaking changes in API responses
- [ ] Environment variables properly configured
- [ ] Database connections working
- [ ] Logging functioning correctly

### Post-Migration Testing
- [ ] Authentication flow works
- [ ] Input validation working
- [ ] Rate limiting functioning
- [ ] Security headers present
- [ ] Error handling working
- [ ] Logging capturing events
- [ ] Performance acceptable

## Common Issues and Solutions

### Issue 1: JWT Token Errors
**Problem**: "Invalid token" errors
**Solution**: 
- Check JWT_SECRET is set correctly
- Verify token format and expiration
- Update client to handle new token structure

### Issue 2: Validation Errors
**Problem**: "Validation failed" errors
**Solution**:
- Check input data format
- Verify required fields are present
- Update client validation

### Issue 3: Rate Limiting
**Problem**: "Too many requests" errors
**Solution**:
- Implement request throttling on client
- Add retry logic with exponential backoff
- Check rate limit configuration

### Issue 4: CORS Errors
**Problem**: CORS policy errors
**Solution**:
- Add your domain to ALLOWED_ORIGINS
- Check CORS configuration
- Verify preflight requests

## Support

### Getting Help
- Check logs in `logs/` directory
- Review error messages in console
- Contact development team

### Documentation
- API Documentation: `/docs`
- Security Guide: `SECURITY.md`
- Environment Setup: `env.example`

## Timeline

### Recommended Migration Timeline
- **Week 1**: Environment setup and testing
- **Week 2**: Client-side updates
- **Week 3**: Integration testing
- **Week 4**: Production deployment

### Critical Path
1. Environment variables setup
2. Database migration
3. Client authentication updates
4. Error handling updates
5. Production deployment

## Success Metrics

### Security Metrics
- Zero critical vulnerabilities in npm audit
- All SonarQube security issues resolved
- Security headers properly configured
- Rate limiting functioning

### Performance Metrics
- Response times within acceptable limits
- No increase in error rates
- Successful authentication rates maintained
- Database performance stable

### Compliance Metrics
- Audit logs capturing all security events
- PII properly masked in logs
- Error messages not leaking sensitive data
- All security policies enforced
