import sys
from pathlib import Path

pisc_root = Path(__file__).parent
sys.path.insert(0, str(pisc_root))
sys.path.insert(0, str(pisc_root / "api"))

from api.security_validation import validate_input, MAX_INPUT_LENGTH

print(f"MAX_INPUT_LENGTH: {MAX_INPUT_LENGTH}")
print(f"MAX_INPUT_LENGTH type: {type(MAX_INPUT_LENGTH)}")

# Test 1: Input exactly at limit
test1 = "a" * MAX_INPUT_LENGTH
result1 = validate_input(test1)
print(f"\nTest 1 (exact limit):")
print(f"  Length: {len(test1)}")
print(f"  Valid: {result1.is_valid}")
print(f"  Errors: {result1.errors}")

# Test 2: Input just over limit
test2 = "a" * (MAX_INPUT_LENGTH + 1)
result2 = validate_input(test2)
print(f"\nTest 2 (over limit):")
print(f"  Length: {len(test2)}")
print(f"  Valid: {result2.is_valid}")
print(f"  Errors: {result2.errors}")
