# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | ✅ Active support  |
| < 1.0   | ❌ Not supported   |

## Reporting a Vulnerability

The SSH Honeypot project takes security seriously. If you discover a security vulnerability, please follow responsible disclosure:

1. **Do not** open a public issue.
2. Report via email: [buildwithpratul@gmail.com](mailto:buildwithpratul@gmail.com)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact
   - Any suggested mitigation (if known)

### What to Expect

- **Acknowledgement** within 48 hours of receipt
- **Validation** within 5 business days
- **Fix timeline** communicated within 10 business days

## Security Best Practices When Using This Tool

### Deployment
- Always run the honeypot behind a firewall with fail2Ban.
- Use the provided Docker container with no-new-privileges.
- Never expose the dashboard or API to the public internet without authentication.
- Use the JWT authentication for API endpoints (`API_JWT_ENABLED=true`).

### Secrets Management
- Keep `.env` files out of version control (`.gitignore` handles this).
- Use environment variables or secrets managers for production deployments.
- Rotate API keys and webhook URLs regularly.
- Never commit GeoIP database files to version control.

### Network
- Isolate the honeypot in a separate network/container.
- Restrict outbound connectivity from the honeypot container.
- Use read-only filesystem mounts for GeoIP databases.
- Monitor container resource usage for signs of abuse.

### Data
- The honeypot never stores passwords or grants shell access.
- Attack logs are stored in SQLite — encrypt the logs volume at rest.
- Regularly rotate logs and archive old data.
- Sanitize any exported data before sharing.

## Known Security Features

- ✅ All authentication attempts rejected (no shell access)
- ✅ Input sanitization against log injection
- ✅ Parameterized SQL queries (no SQL injection)
- ✅ XSS escaping in dashboard HTML
- ✅ No plaintext password storage
- ✅ Rate limiting via brute-force detection
- ✅ Optional JWT authentication for API
- ✅ Docker with non-root user
- ✅ `no-new-privileges` security option in Docker