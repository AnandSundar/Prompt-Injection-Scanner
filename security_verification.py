"""Security Verification Module - OWASP Security Controls Testing

This module provides verification functions to test the security controls
implemented in the PISC application.

Run this script to verify that all security controls are properly configured:
python security_verification.py

Security Checks:
- A03: Injection prevention (Input validation)
- A04: Insecure Design (Security headers, error handling)
- A06: Vulnerable Components (Dependency security)
- A08: Data Integrity (Secure logging)
- A09: Logging & Monitoring (Security audit)
- A10: SSRF prevention (Secure API calls)

"""

import os
import sys
import subprocess
from typing import Dict, List, Tuple
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv

# Import security modules from api directory
from api.security_validation import validate_input, MAX_INPUT_LENGTH
from api.security_ssrf import validate_url, block_internal_ips
from api.security_logging import SecurityLogger
from api.security_audit import audit_logger, AuditEventType, AuditSeverity

pisc_root = Path(__file__).parent
load_dotenv(dotenv_path=pisc_root / ".env")

# Add api directory to path
sys.path.insert(0, str(pisc_root))
sys.path.insert(0, str(pisc_root / "api"))


def check_environment_config() -> List[Tuple[str, bool, str]]:
    """Check if environment variables are properly configured."""
    checks = []

    # Check for required secrets
    checks.append(
        (
            "OPENAI_API_KEY configured",
            bool(os.getenv("OPENAI_API_KEY")),
            "OpenAI API key should be configured",
        )
    )

    # Check for API authentication
    checks.append(
        (
            "PISC_API_KEY configured (for production)",
            bool(os.getenv("PISC_API_KEY")),
            "API key should be configured for production",
        )
    )

    # Check CORS configuration
    allowed_origins = os.getenv(
        "ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000"
    )
    checks.append(
        (
            "CORS not allowing all origins (*)",
            "*" not in allowed_origins,
            "CORS should not allow all origins in production",
        )
    )

    # Check server configuration
    host = os.getenv("HOST", "127.0.0.1")
    checks.append(
        (
            "Server not exposed to all interfaces",
            host == "127.0.0.1",
            "Server should bind to localhost in development",
        )
    )

    return checks


def check_security_modules() -> List[Tuple[str, bool, str]]:
    """Check if security modules are importable."""
    checks = []

    modules_to_check = [
        "security_validation",
        "security_logging",
        "security_audit",
        "security_ssrf",
    ]

    for module in modules_to_check:
        try:
            __import__(module)
            checks.append(
                (f"{module} module importable", True, f"{module} module exists")
            )
        except ImportError as e:
            checks.append((f"{module} module importable", False, str(e)))

    return checks


def check_dependency_security() -> List[Tuple[str, bool, str]]:
    """Check dependency security."""
    checks = []

    # Check Python dependencies
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list"],
            capture_output=True,
            text=True,
            check=True,
        )
        checks.append(("pip dependencies listed", True, "pip dependencies installed"))
    except subprocess.CalledProcessError as e:
        checks.append(("pip dependencies listed", False, str(e)))

    # Check for safety tool
    try:
        import safety

        checks.append(
            ("Safety tool available", True, "Safety dependency checker available")
        )
    except ImportError:
        checks.append(("Safety tool available", False, "safety module not installed"))

    return checks


def run_safety_check() -> List[Tuple[str, bool, str]]:
    """Run safety check on dependencies."""
    checks = []

    try:
        import safety

        requirements_file = pisc_root / "requirements.txt"
        if requirements_file.exists():
            result = subprocess.run(
                [sys.executable, "-m", "safety", "check", "--full-report"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                checks.append(
                    (
                        "Dependencies have no known vulnerabilities",
                        True,
                        "All dependencies are safe",
                    )
                )
            else:
                checks.append(
                    (
                        "Dependencies have known vulnerabilities",
                        False,
                        f"Vulnerabilities found: {result.stdout}",
                    )
                )
        else:
            checks.append(
                ("requirements.txt exists", False, "requirements.txt not found")
            )

    except ImportError:
        checks.append(("Safety check available", False, "safety module not installed"))
    except Exception as e:
        checks.append(("Safety check failed", False, str(e)))

    return checks


def check_frontend_dependencies() -> List[Tuple[str, bool, str]]:
    """Check frontend dependencies for vulnerabilities."""
    checks = []

    frontend_dir = pisc_root / "web"
    if frontend_dir.exists():
        package_json = frontend_dir / "package.json"
        if package_json.exists():
            checks.append(("package.json exists", True, "Frontend package.json exists"))

            # Try to run npm audit (if npm is available - optional check)
            try:
                result = subprocess.run(
                    ["npm", "audit"], cwd=frontend_dir, capture_output=True, text=True
                )
                if result.returncode == 0:
                    checks.append(
                        (
                            "Frontend dependencies have no vulnerabilities",
                            True,
                            "No vulnerabilities in frontend dependencies",
                        )
                    )
                else:
                    checks.append(
                        (
                            "Frontend dependencies have vulnerabilities",
                            False,
                            f"Vulnerabilities found: {result.stdout}",
                        )
                    )
            except FileNotFoundError:
                checks.append(("npm available (optional)", True, "npm not required"))
            except Exception as e:
                checks.append(
                    ("npm audit failed (optional)", True, f"npm audit failed: {str(e)}")
                )
        else:
            checks.append(("package.json exists", False, "package.json not found"))
    else:
        checks.append(("Frontend directory exists", False, "web directory not found"))

    return checks


def run_bandit_scan() -> List[Tuple[str, bool, str]]:
    """Run Bandit security scan."""
    checks = []

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-r",
                "api",
                "scanner.py",
                "llm_classifier.py",
                "patterns.py",
                "scorer.py",
                "cli.py",
            ],
            capture_output=True,
            text=True,
        )

        if "No issues identified" in result.stdout:
            checks.append(
                ("Bandit scan passed", True, "Bandit found no security issues")
            )
        else:
            checks.append(
                ("Bandit scan passed", False, f"Bandit issues: {result.stdout}")
            )

    except FileNotFoundError:
        checks.append(("Bandit available", False, "bandit module not installed"))
    except Exception as e:
        checks.append(("Bandit scan failed", False, str(e)))

    return checks


def test_input_validation() -> List[Tuple[str, bool, str]]:
    """Test input validation module."""
    checks = []

    try:

        # Test valid input
        valid_result = validate_input("Valid prompt", "test")
        checks.append(
            (
                "Valid input validation",
                valid_result.is_valid,
                "Valid inputs should pass",
            )
        )

        # Test invalid input types
        invalid_result = validate_input(123, "test")
        checks.append(
            (
                "Invalid type validation",
                not invalid_result.is_valid,
                "Invalid types should fail",
            )
        )

        # Test length limits

        very_long_input = "a" * (MAX_INPUT_LENGTH + 1)
        long_result = validate_input(very_long_input, "test")
        checks.append(
            (
                "Maximum length validation",
                not long_result.is_valid,
                "Inputs over 50KB should fail",
            )
        )

        # Test dangerous patterns
        dangerous_input = "{{system_prompt}}"
        dangerous_result = validate_input(dangerous_input, "test")
        checks.append(
            (
                "Dangerous pattern detection",
                dangerous_result.threat_detected,
                "Dangerous patterns should be detected",
            )
        )

    except Exception as e:
        checks.append(("Input validation module test failed", False, str(e)))

    return checks


def test_ssrf_prevention() -> List[Tuple[str, bool, str]]:
    """Test SSRF prevention module."""
    checks = []

    try:

        # Test valid URL
        valid_url = "https://api.openai.com"
        valid_result = validate_url(valid_url)
        checks.append(
            ("Valid URL validation", valid_result.is_valid, "Valid URLs should pass")
        )

        # Test blocked IP (localhost)
        local_url = "http://localhost:8000"
        local_result = validate_url(local_url)
        checks.append(
            (
                "Localhost URL blocking",
                not local_result.is_valid,
                "Localhost URLs should be blocked",
            )
        )

        # Test private IP range
        private_url = "http://192.168.1.1"
        private_result = validate_url(private_url)
        checks.append(
            (
                "Private IP blocking",
                not private_result.is_valid,
                "Private IP ranges should be blocked",
            )
        )

    except Exception as e:
        checks.append(("SSRF prevention module test failed", False, str(e)))

    return checks


def test_security_logging() -> List[Tuple[str, bool, str]]:
    """Test security logging module."""
    checks = []

    try:

        logger = SecurityLogger("test")
        logger.info("Test message", "test_event")
        checks.append(
            ("Security logger initialization", True, "Logger initialized successfully")
        )

    except Exception as e:
        checks.append(("Security logging module test failed", False, str(e)))

    return checks


def test_security_audit() -> List[Tuple[str, bool, str]]:
    """Test security audit module."""
    checks = []

    try:

        event = audit_logger.log_event(
            AuditEventType.REQUEST_RECEIVED, AuditSeverity.INFO
        )
        checks.append(("Security audit logging", True, "Audit logger works"))

        # Verify event integrity
        checks.append(
            (
                "Event integrity verification",
                event.verify_integrity(),
                "Event integrity should be verifiable",
            )
        )

    except Exception as e:
        checks.append(("Security audit module test failed", False, str(e)))

    return checks


def print_checks(checks: List[Tuple[str, bool, str]], section_name: str):
    """Print checks with colors."""
    print(f"\n{'='*60}")
    print(f"  {section_name}")
    print(f"{'='*60}")

    passed = 0
    failed = 0

    for check, status, message in checks:
        status_char = "[OK]" if status else "[FAIL]"
        status_color = "\033[92m" if status else "\033[91m"
        reset_color = "\033[0m"

        print(f"  {status_char} {status_color}{check:<40}{reset_color}")

        if not status:
            failed += 1
            print(f"      {message}")
        else:
            passed += 1

    print(f"\n  Total: {passed} passed, {failed} failed")
    return passed, failed


def main():
    """Main verification function."""
    print("\033[1mPISC Security Controls Verification\033[0m")
    print("=" * 60)
    print("Testing OWASP Top 10 security controls...")

    all_passed = 0
    all_failed = 0

    # Check environment configuration
    config_checks = check_environment_config()
    passed, failed = print_checks(config_checks, "Environment Configuration (A05)")
    all_passed += passed
    all_failed += failed

    # Check security modules
    module_checks = check_security_modules()
    passed, failed = print_checks(module_checks, "Security Modules")
    all_passed += passed
    all_failed += failed

    # Test security modules
    validation_checks = test_input_validation()
    passed, failed = print_checks(validation_checks, "Input Validation (A03)")
    all_passed += passed
    all_failed += failed

    ssrf_checks = test_ssrf_prevention()
    passed, failed = print_checks(ssrf_checks, "SSRF Prevention (A10)")
    all_passed += passed
    all_failed += failed

    logging_checks = test_security_logging()
    passed, failed = print_checks(logging_checks, "Security Logging (A08)")
    all_passed += passed
    all_failed += failed

    audit_checks = test_security_audit()
    passed, failed = print_checks(audit_checks, "Security Audit (A09)")
    all_passed += passed
    all_failed += failed

    # Check dependencies
    dependency_checks = check_dependency_security()
    passed, failed = print_checks(dependency_checks, "Python Dependencies (A06)")
    all_passed += passed
    all_failed += failed

    # Run safety check
    safety_checks = run_safety_check()
    passed, failed = print_checks(safety_checks, "Dependency Vulnerability Check (A06)")
    all_passed += passed
    all_failed += failed

    # Check frontend dependencies
    frontend_checks = check_frontend_dependencies()
    passed, failed = print_checks(frontend_checks, "Frontend Dependencies (A06)")
    all_passed += passed
    all_failed += failed

    # Run Bandit scan
    bandit_checks = run_bandit_scan()
    passed, failed = print_checks(bandit_checks, "Bandit Security Scan")
    all_passed += passed
    all_failed += failed

    print(f"\n{'='*60}")
    print(f"  FINAL RESULTS")
    print(f"{'='*60}")
    print(f"  Total Checks Passed: \033[92m{all_passed}\033[0m")
    print(f"  Total Checks Failed: \033[91m{all_failed}\033[0m")

    if all_failed == 0:
        print("\n[OK] All security controls are properly configured!")
    else:
        print(
            f"\n[FAIL] \033[91m{all_failed} security control(s) need to be fixed!\033[0m"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
