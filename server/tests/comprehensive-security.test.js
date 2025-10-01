const request = require('supertest');
const app = require('../server');
const jwt = require('jsonwebtoken');
const Staff = require('../Models/Staff');

describe('Comprehensive Security Tests', () => {
  let staffToken;
  let merchantToken;
  let testStaff;

  beforeAll(async() => {
    // Create test staff member
    testStaff = new Staff({
      firstName: 'Test',
      lastName: 'Admin',
      email: 'testadmin@example.com',
      password: 'TestPass123!',
      role: 'admin',
      permissions: ['users.read', 'users.write', 'transactions.read', 'transactions.write']
    });
    await testStaff.save();

    // Generate tokens
    staffToken = jwt.sign(
      {
        staffId: testStaff._id,
        email: testStaff.email,
        role: testStaff.role,
        permissions: testStaff.permissions,
        type: 'staff'
      },
      process.env.JWT_SECRET || 'test-secret',
      { expiresIn: '1h' }
    );

    merchantToken = jwt.sign(
      {
        userId: '507f1f77bcf86cd799439011',
        email: 'merchant@example.com',
        type: 'merchant'
      },
      process.env.JWT_SECRET || 'test-secret',
      { expiresIn: '1h' }
    );
  });

  afterAll(async() => {
    await Staff.deleteOne({ _id: testStaff._id });
  });

  describe('Staff Authentication & Authorization', () => {
    test('should allow staff login with valid credentials', async() => {
      const response = await request(app)
        .post('/api/staff/login')
        .send({
          email: 'testadmin@example.com',
          password: 'TestPass123!'
        });

      expect(response.status).toBe(200);
      expect(response.body.token).toBeDefined();
      expect(response.body.staff).toBeDefined();
    });

    test('should reject staff login with invalid credentials', async() => {
      const response = await request(app)
        .post('/api/staff/login')
        .send({
          email: 'testadmin@example.com',
          password: 'wrongpassword'
        });

      expect(response.status).toBe(401);
      expect(response.body.error).toContain('Invalid credentials');
    });

    test('should allow staff to access staff endpoints', async() => {
      const response = await request(app)
        .get('/api/staff/')
        .set('Authorization', `Bearer ${staffToken}`);

      expect(response.status).toBe(200);
    });

    test('should reject merchant access to staff endpoints', async() => {
      const response = await request(app)
        .get('/api/staff/')
        .set('Authorization', `Bearer ${merchantToken}`);

      expect(response.status).toBe(403);
      expect(response.body.error).toContain('Staff access required');
    });
  });

  describe('Role-Based Access Control', () => {
    test('should allow admin to create staff members', async() => {
      const response = await request(app)
        .post('/api/staff/register')
        .set('Authorization', `Bearer ${staffToken}`)
        .send({
          firstName: 'New',
          lastName: 'Staff',
          email: 'newstaff@example.com',
          password: 'NewPass123!',
          role: 'support'
        });

      expect(response.status).toBe(201);
      expect(response.body.staff).toBeDefined();
    });

    test('should reject viewer from creating staff members', async() => {
      const viewerToken = jwt.sign(
        {
          staffId: testStaff._id,
          email: testStaff.email,
          role: 'viewer',
          permissions: [],
          type: 'staff'
        },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '1h' }
      );

      const response = await request(app)
        .post('/api/staff/register')
        .set('Authorization', `Bearer ${viewerToken}`)
        .send({
          firstName: 'New',
          lastName: 'Staff',
          email: 'newstaff2@example.com',
          password: 'NewPass123!',
          role: 'support'
        });

      expect(response.status).toBe(403);
    });
  });

  describe('Input Validation', () => {
    test('should reject invalid email format in staff registration', async() => {
      const response = await request(app)
        .post('/api/staff/register')
        .set('Authorization', `Bearer ${staffToken}`)
        .send({
          firstName: 'Test',
          lastName: 'User',
          email: 'invalid-email',
          password: 'ValidPass123!',
          role: 'support'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Validation failed');
    });

    test('should reject weak password in staff registration', async() => {
      const response = await request(app)
        .post('/api/staff/register')
        .set('Authorization', `Bearer ${staffToken}`)
        .send({
          firstName: 'Test',
          lastName: 'User',
          email: 'test@example.com',
          password: 'weak',
          role: 'support'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Validation failed');
    });

    test('should reject invalid role in staff registration', async() => {
      const response = await request(app)
        .post('/api/staff/register')
        .set('Authorization', `Bearer ${staffToken}`)
        .send({
          firstName: 'Test',
          lastName: 'User',
          email: 'test@example.com',
          password: 'ValidPass123!',
          role: 'invalid_role'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Validation failed');
    });
  });

  describe('Bank Details Security', () => {
    test('should require authentication for bank details access', async() => {
      const response = await request(app)
        .get('/api/bankDetails/507f1f77bcf86cd799439011');

      expect(response.status).toBe(401);
    });

    test('should validate bank account number format', async() => {
      const response = await request(app)
        .post('/api/bankDetails/507f1f77bcf86cd799439011')
        .set('Authorization', `Bearer ${staffToken}`)
        .send({
          accountNumber: '123', // Invalid format
          holderName: 'John Doe',
          bankName: 'Test Bank',
          branchName: 'Test Branch',
          ifsc: 'TEST0001234'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Validation failed');
    });

    test('should validate IFSC code format', async() => {
      const response = await request(app)
        .post('/api/bankDetails/507f1f77bcf86cd799439011')
        .set('Authorization', `Bearer ${staffToken}`)
        .send({
          accountNumber: '1234567890',
          holderName: 'John Doe',
          bankName: 'Test Bank',
          branchName: 'Test Branch',
          ifsc: 'INVALID' // Invalid IFSC format
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Validation failed');
    });
  });

  describe('File Upload Security', () => {
    test('should require authentication for file upload', async() => {
      const response = await request(app)
        .post('/api/logo/upload/507f1f77bcf86cd799439011');

      expect(response.status).toBe(401);
    });

    test('should reject non-image files', async() => {
      const response = await request(app)
        .post('/api/logo/upload/507f1f77bcf86cd799439011')
        .set('Authorization', `Bearer ${staffToken}`)
        .attach('profile', Buffer.from('fake content'), 'test.txt');

      expect(response.status).toBe(400);
    });

    test('should reject oversized files', async() => {
      // Create a large buffer (6MB)
      const largeBuffer = Buffer.alloc(6 * 1024 * 1024, 'a');

      const response = await request(app)
        .post('/api/logo/upload/507f1f77bcf86cd799439011')
        .set('Authorization', `Bearer ${staffToken}`)
        .attach('profile', largeBuffer, 'large.jpg');

      expect(response.status).toBe(400);
    });
  });

  describe('API Key Security', () => {
    test('should require staff authentication for API key generation', async() => {
      const response = await request(app)
        .post('/api/generate-api-key')
        .send({
          merchantId: '507f1f77bcf86cd799439011'
        });

      expect(response.status).toBe(401);
    });

    test('should require proper permissions for API key operations', async() => {
      const viewerToken = jwt.sign(
        {
          staffId: testStaff._id,
          email: testStaff.email,
          role: 'viewer',
          permissions: [],
          type: 'staff'
        },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '1h' }
      );

      const response = await request(app)
        .post('/api/generate-api-key')
        .set('Authorization', `Bearer ${viewerToken}`)
        .send({
          merchantId: '507f1f77bcf86cd799439011'
        });

      expect(response.status).toBe(403);
    });
  });

  describe('Whitelist Security', () => {
    test('should require authentication for whitelist access', async() => {
      const response = await request(app)
        .get('/api/whitelist/507f1f77bcf86cd799439011');

      expect(response.status).toBe(401);
    });

    test('should validate whitelist URL format', async() => {
      const response = await request(app)
        .post('/api/whitelist/507f1f77bcf86cd799439011')
        .set('Authorization', `Bearer ${staffToken}`)
        .send({
          type: 'domain',
          link: 'invalid-url' // Invalid URL format
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Validation failed');
    });

    test('should validate whitelist type', async() => {
      const response = await request(app)
        .post('/api/whitelist/507f1f77bcf86cd799439011')
        .set('Authorization', `Bearer ${staffToken}`)
        .send({
          type: 'invalid_type',
          link: 'https://example.com'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Validation failed');
    });
  });

  describe('Rate Limiting', () => {
    test('should apply rate limiting to authentication endpoints', async() => {
      const promises = [];

      // Make multiple requests to trigger rate limiting
      for (let i = 0; i < 10; i++) {
        promises.push(
          request(app)
            .post('/api/staff/login')
            .send({
              email: 'testadmin@example.com',
              password: 'wrongpassword'
            })
        );
      }

      const responses = await Promise.all(promises);
      const rateLimitedResponses = responses.filter(r => r.status === 429);

      // Should have some rate limited responses
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });
  });

  describe('Security Headers', () => {
    test('should include security headers in all responses', async() => {
      const response = await request(app)
        .get('/');

      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['x-xss-protection']).toBe('1; mode=block');
    });
  });

  describe('Error Handling', () => {
    test('should not leak sensitive information in error responses', async() => {
      const response = await request(app)
        .post('/api/staff/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'password'
        });

      expect(response.status).toBe(401);
      expect(response.body.error).not.toContain('stack');
      expect(response.body.error).not.toContain('password');
      expect(response.body.error).not.toContain('secret');
    });
  });

  describe('CORS Security', () => {
    test('should reject requests from unauthorized origins', async() => {
      const response = await request(app)
        .get('/')
        .set('Origin', 'https://malicious-site.com');

      // Should either reject or not include CORS headers for unauthorized origin
      expect(response.headers['access-control-allow-origin']).not.toBe('https://malicious-site.com');
    });
  });
});
