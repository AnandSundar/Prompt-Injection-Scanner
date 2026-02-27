import sys
from pathlib import Path

pisc_root = Path(__file__).parent
sys.path.insert(0, str(pisc_root))
sys.path.insert(0, str(pisc_root / "api"))

print("Testing security modules...")
print("=" * 50)

# Test 1: security_validation
try:
    from api.security_validation import validate_input

    print("[OK] security_validation module imported")

    # Test simple validation
    result = validate_input("Hello world")
    print(
        "  - Simple validation: Passed"
        if result.is_valid
        else "  - Simple validation: Failed"
    )

except Exception as e:
    print("[FAIL] security_validation:", e)
    import traceback

    print(traceback.format_exc())

# Test 2: security_logging
try:
    from api.security_logging import SecurityLogger

    print("[OK] security_logging module imported")

    logger = SecurityLogger("test")
    logger.info("Test message", "test_event")
    print("  - Logger created and tested")

except Exception as e:
    print("[FAIL] security_logging:", e)
    import traceback

    print(traceback.format_exc())

# Test 3: security_audit
try:
    from api.security_audit import audit_logger, AuditEventType, AuditSeverity

    print("[OK] security_audit module imported")

    event = audit_logger.log_event(AuditEventType.REQUEST_RECEIVED, AuditSeverity.INFO)
    print("  - Audit event created:", event.event_id)
    print(
        "  - Integrity check: Passed"
        if event.verify_integrity()
        else "  - Integrity check: Failed"
    )

except Exception as e:
    print("[FAIL] security_audit:", e)
    import traceback

    print(traceback.format_exc())

# Test 4: security_ssrf
try:
    from api.security_ssrf import validate_url

    print("[OK] security_ssrf module imported")

    valid_url = "https://api.openai.com"
    invalid_url = "http://localhost:8000"

    valid_result = validate_url(valid_url)
    invalid_result = validate_url(invalid_url)

    print(
        "  - Valid URL (",
        valid_url,
        "): Valid" if valid_result.is_valid else "Invalid",
        sep="",
    )
    print(
        "  - Invalid URL (",
        invalid_url,
        "): Invalid" if not invalid_result.is_valid else "Valid",
        sep="",
    )

except Exception as e:
    print("[FAIL] security_ssrf:", e)
    import traceback

    print(traceback.format_exc())

print("\n" + "=" * 50)
print("All modules tested!")
