# PISC Security Documentation

This document provides comprehensive documentation of the security controls implemented in the PISC (Prompt Injection Scanner) application.

## OWASP Top 10 Security Controls

### A03:2021 - Injection Prevention (Input Validation)

**Implementation Status:** ✓ Complete

**Location:** [`api/security_validation.py`](api/security_validation.py)

**Features:**
- Input length validation (1-50KB)
- Type validation (must be string)
- Unicode normalization
- Dangerous pattern detection
- Null byte removal
- Special character sanitization

**Key Methods:**
- `validate_input()` - Comprehensive validation function
- `validate_prompt()` - Convenience function for prompt validation
- `check_injection_patterns()` - Pattern detection
- `prompt_validator()` - Pydantic validator for API models

**Integration:**
- Used in [`ScanRequest` model](api/main.py:182) for API input validation
- LLM classifier input validation in [`llm_classifier.py`](llm_classifier.py)
- Scanner input validation in [`scanner.py`](scanner.py)

### A04:2021 - Insecure Design

**Implementation Status:** ✓ Complete

**Security Headers:**
- **X-Content-Type-Options:** `nosniff` - Prevents MIME type sniffing
- **X-Frame-Options:** `DENY` - Prevents clickjacking
- **X-XSS-Protection:** `1; mode=block` - XSS protection
- **Strict-Transport-Security:** `max-age=31536000; includeSubDomains` - HSTS
- **Content-Security-Policy:** `default-src 'self'` - CSP

**Location:** [`api/main.py:474-481`](api/main.py:474-481)

**Error Handling:**
- Centralized exception handling with sanitized error messages
- Validation error handler with safe user feedback
- General exception handler with minimal information leakage

**Location:** [`api/main.py:429-461`](api/main.py:429-461)

### A06:2021 - Vulnerable and Outdated Components

**Implementation Status:** ✓ Complete

**Dependency Management:**

**Python (Backend):**
- [`requirements.txt`](requirements.txt) - Explicit dependency versions
- Safety tool integration - `safety check`
- Bandit static analyzer - `bandit -r`
- Pip audit support - `pip-audit`

**Frontend (React):**
- [`web/package.json`](web/package.json) with security scripts
- `npm audit` - Check for vulnerabilities
- `npm audit fix` - Auto-fix vulnerabilities

**Security Scripts:**
```bash
# Python security checks
python -m pip install -r requirements.txt
python -m safety check
python -m bandit -r api scanner.py llm_classifier.py

# Frontend security checks
cd web
npm audit
npm run check:security
```

**Dependency Verification:**
- [`security_verification.py`](security_verification.py) automatically checks dependencies
- Requirement files include explicit version constraints
- Regular audit process recommended

### A08:2021 - Software and Data Integrity Failures

**Implementation Status:** ✓ Complete

**Secure Logging:**
- No sensitive data logging (API keys, passwords, tokens)
- Prompt hashing for log entries
- Truncation of long strings
- JSON structured logging
- Rotating file handlers
- Console and file output support

**Location:** [`api/security_logging.py`](api/security_logging.py)

**Key Features:**
- `SecureJSONFormatter` - Sanitizes logs before output
- `SecurityLogger` - Main logger class with correlation IDs
- `log_scan_event()` - Scan-specific logging
- `log_security_event()` - Security event logging
- Sanitization of sensitive data fields

### A09:2021 - Security Logging and Monitoring Failures

**Implementation Status:** ✓ Complete

**Security Audit Logging:**
- Structured security audit events
- Integrity verification with SHA-256 hashes
- Comprehensive event types
- Audit severity levels
- Compliance-friendly format

**Location:** [`api/security_audit.py`](api/security_audit.py)

**Audit Event Types:**
```python
- AUTH_SUCCESS / AUTH_FAILURE - Authentication events
- ACCESS_DENIED / ACCESS_GRANTED - Authorization events
- REQUEST_RECEIVED / REQUEST_COMPLETED - Request events
- INJECTION_DETECTED / SSRF_ATTEMPT - Security threats
- RATE_LIMIT_EXCEEDED / INVALID_INPUT - API protection
- SCAN_STARTED / SCAN_COMPLETED - Scan operations
```

**Key Methods:**
- `SecurityAuditLogger.log_event()` - Log audit events
- `AuditEvent.verify_integrity()` - Verify event hash
- Convenience methods for common events (log_auth_success(), log_injection_detected(), etc.)

### A10:2021 - Server-Side Request Forgery (SSRF)

**Implementation Status:** ✓ Complete

**SSRF Prevention:**
- URL validation and allowlist checking
- DNS rebinding protection with caching
- Request timeout enforcement
- IP address blocking (internal networks)
- Allowed hosts configuration

**Location:** [`api/security_ssrf.py`](api/security_ssrf.py)

**Key Features:**
- Blocks private/internal IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Blocks localhost and loopback addresses
- Validates API endpoints against known safe hosts
- Default 30-second timeout for requests
- DNS cache with TTL to prevent rebinding attacks

**Methods:**
- `validate_url()` - Comprehensive URL validation
- `validate_openai_endpoint()` - OpenAI-specific validation
- `block_internal_ips()` - Check if IP is internal
- `SSRFProtection` class for SSRF protection

## Additional Security Controls

### A01:2021 - Broken Access Control

**Features:**
- CORS with restricted origins
- API key authentication
- Rate limiting (60 requests/minute per IP)
- Endpoint protection middleware

**Location:** [`api/main.py`](api/main.py)

### A02:2021 - Cryptographic Failures

**Features:**
- No sensitive data logging
- Environment variable configuration
- Secret validation on startup
- API key validation

**Location:** [`api/main.py`](api/main.py), [`api/security_logging.py`](api/security_logging.py)

### A05:2021 - Security Misconfiguration

**Features:**
- Server bind address configuration (localhost by default)
- Request size limits (100KB)
- Production/development environment detection
- Security header middleware

**Location:** [`api/main.py`](api/main.py), [`api/run.py`](api/run.py)

### A07:2021 - Identification and Authentication Failures

**Features:**
- API key authentication
- Middleware authentication
- Header-based API key validation
- Public/private endpoint segregation

**Location:** [`api/main.py`](api/main.py)

## Security Verification

**Verification Tool:** [`security_verification.py`](security_verification.py)

**Usage:**
```bash
# Run full security verification
python security_verification.py

# Expected output:
# ✅ All security controls are properly configured!
```

**What's Verified:**
- Environment configuration (API keys, CORS, server settings)
- Security modules importability
- Input validation
- SSRF prevention
- Security logging
- Security audit system
- Dependency security
- Frontend dependencies
- Bandit static analysis

## Configuration

**Environment Variables:**

```bash
# API Configuration (A07)
PISC_API_KEY=your-secure-api-key  # Generate with: python -c "import secrets; print(secrets.token_hex(32))"

# LLM Configuration
OPENAI_API_KEY=your-openai-api-key

# CORS Configuration (A01)
ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000

# Server Configuration (A05)
HOST=127.0.0.1  # Bind to localhost
PORT=8000
```

## Security Best Practices

### Development:
1. Use `ENV=development` for local testing
2. Generate secure API keys using `python -c "import secrets; print(secrets.token_hex(32))"`
3. Run security verification before each commit: `python security_verification.py`

### Production:
1. Set `ENV=production`
2. Configure `PISC_API_KEY` with a secure value
3. Restrict `ALLOWED_ORIGINS` to specific domains
4. Disable debug mode
5. Use HTTPS
6. Regularly update dependencies
7. Monitor security logs

### Regular Maintenance:
1. Run dependency audits monthly:
   - Python: `python -m pip list --outdated` and `python -m safety check`
   - Frontend: `cd web && npm audit`
2. Review security logs regularly
3. Update security patterns in [`api/security_validation.py`](api/security_validation.py)
4. Test new features with security verification script

## Incident Response

**Security Events to Monitor:**
- `auth_failure` - Failed authentication attempts
- `injection_detected` - Prompt injection attempts
- `ssrf_attempt` - SSRF attempts
- `rate_limit_exceeded` - Rate limiting triggers
- `invalid_input` - Invalid input patterns

**Audit Log Location:** `logs/security_audit.log`

**Response Actions:**
1. Identify the source IP address from audit logs
2. Block suspicious IP addresses
3. Analyze the attack pattern
4. Update security patterns if needed
5. Review API keys and secrets

## Conclusion

PISC implements comprehensive security controls addressing all OWASP Top 10 (2021) vulnerabilities. The security architecture includes:

- **Preventive Controls:** Input validation, SSRF protection, authentication
- **Detective Controls:** Security audit logging, pattern detection
- **Corrective Controls:** Error handling, rate limiting
- **Documentation:** Complete security documentation and verification

Regular security audits and maintenance are essential to maintain the security posture.
