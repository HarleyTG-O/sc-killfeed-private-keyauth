#!/usr/bin/env python3
"""
Test KeyAuth library import to find correct usage
"""

print("Testing KeyAuth library imports...")

# Test 1: Try importing keyauth module
try:
    import keyauth
    print("✓ import keyauth - SUCCESS")
    print(f"  keyauth module: {keyauth}")
    print(f"  keyauth dir: {dir(keyauth)}")
except ImportError as e:
    print(f"❌ import keyauth - FAILED: {e}")

# Test 2: Try importing keyauth.api
try:
    from keyauth import api
    print("✓ from keyauth import api - SUCCESS")
    print(f"  api: {api}")
    print(f"  api type: {type(api)}")
except ImportError as e:
    print(f"❌ from keyauth import api - FAILED: {e}")

# Test 3: Try different import patterns
try:
    import keyauth.api
    print("✓ import keyauth.api - SUCCESS")
    print(f"  keyauth.api: {keyauth.api}")
except ImportError as e:
    print(f"❌ import keyauth.api - FAILED: {e}")

# Test 4: Try KeyAuth class import
try:
    from keyauth.api import KeyAuth
    print("✓ from keyauth.api import KeyAuth - SUCCESS")
    print(f"  KeyAuth: {KeyAuth}")
except ImportError as e:
    print(f"❌ from keyauth.api import KeyAuth - FAILED: {e}")

# Test 5: Try alternative patterns
try:
    from keyauth import KeyAuth
    print("✓ from keyauth import KeyAuth - SUCCESS")
    print(f"  KeyAuth: {KeyAuth}")
except ImportError as e:
    print(f"❌ from keyauth import KeyAuth - FAILED: {e}")

print("\nTesting complete. Use the successful import pattern.")
