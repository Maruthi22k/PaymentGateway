const request = require('supertest');
const app = require('../server');
const jwt = require('jsonwebtoken');

describe('Security Tests', () => {
  describe('Authentication', () => {
    test('should reject requests without token', async() => {
      const response = await request(app)
        .post('/api/user')
        .send({ _id: '507f1f77bcf86cd799439011' });

      expect(response.status).toBe(401);
      expect(response.body.error).toContain('Access denied');
    });

    test('should reject requests with invalid token', async() => {
      const response = await request(app)
        .post('/api/user')
        .set('Authorization', 'Bearer invalid-token')
        .send({ _id: '507f1f77bcf86cd799439011' });

      expect(response.status).toBe(401);
      expect(response.body.error).toContain('Access denied');
    });

    test('should reject requests with expired token', async() => {
      const expiredToken = jwt.sign(
        { userId: '507f1f77bcf86cd799439011' },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '-1h' }
      );

      const response = await request(app)
        .post('/api/user')
        .set('Authorization', `Bearer ${expiredToken}`)
        .send({ _id: '507f1f77bcf86cd799439011' });

      expect(response.status).toBe(401);
      expect(response.body.error).toContain('Access denied');
    });
  });

  describe('Input Validation', () => {
    test('should reject invalid email format', async() => {
      const response = await request(app)
        .post('/api/register')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'invalid-email',
          password: 'ValidPass123!',
          mobile: '9876543210'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Validation failed');
    });

    test('should reject weak password', async() => {
      const response = await request(app)
        .post('/api/register')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'test@example.com',
          password: 'weak',
          mobile: '9876543210'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Validation failed');
    });

    test('should reject invalid mobile number', async() => {
      const response = await request(app)
        .post('/api/register')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'test@example.com',
          password: 'ValidPass123!',
          mobile: '123'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Validation failed');
    });
  });

  describe('Rate Limiting', () => {
    test('should apply rate limiting to auth endpoints', async() => {
      const promises = [];

      // Make multiple requests to trigger rate limiting
      for (let i = 0; i < 10; i++) {
        promises.push(
          request(app)
            .post('/api/login')
            .send({
              email: 'test@example.com',
              password: 'password'
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
    test('should include security headers', async() => {
      const response = await request(app)
        .get('/');

      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['x-xss-protection']).toBe('1; mode=block');
    });
  });

  describe('Error Handling', () => {
    test('should not leak sensitive information in errors', async() => {
      const response = await request(app)
        .post('/api/user')
        .send({ _id: 'invalid-id' });

      expect(response.status).toBe(401);
      expect(response.body.error).not.toContain('stack');
      expect(response.body.error).not.toContain('password');
      expect(response.body.error).not.toContain('secret');
    });
  });

  describe('CORS', () => {
    test('should reject requests from unauthorized origins', async() => {
      const response = await request(app)
        .get('/')
        .set('Origin', 'https://malicious-site.com');

      // Should either reject or not include CORS headers
      expect(response.headers['access-control-allow-origin']).not.toBe('https://malicious-site.com');
    });
  });
});
