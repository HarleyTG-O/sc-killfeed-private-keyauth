#!/usr/bin/env python3
"""
Test the fixed KeyAuth integration
"""

import sys
import os
import json
import hashlib
import platform
import base64
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configuration paths
CONFIG_DIR = Path(os.getenv('LOCALAPPDATA')) / "Harley's Studio" / "Star Citizen Kill Tracker"
CONFIG_FILE = CONFIG_DIR / "keyauth_config.json"
SECRET_FILE = CONFIG_DIR / "keyauth_secret.enc"

def test_keyauth_import():
    """Test KeyAuth library import"""
    print("Testing KeyAuth library import...")

    try:
        from keyauth import Keyauth
        print("✓ KeyAuth library imported successfully")
        return True
    except ImportError as e:
        print(f"❌ KeyAuth import failed: {e}")
        print("Install with: pip install keyauth")
        return False

def test_config_files():
    """Test configuration files"""
    print("\nTesting configuration files...")

    # Check config file
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            print("✓ Configuration file found and valid")
            print(f"  App Name: {config.get('app_name', 'Not set')}")
            print(f"  Owner ID: {config.get('owner_id', 'Not set')}")
            print(f"  Version: {config.get('version', 'Not set')}")
        except Exception as e:
            print(f"❌ Configuration file error: {e}")
            return False
    else:
        print("❌ Configuration file not found")
        return False

    # Check secret file
    if SECRET_FILE.exists():
        print("✓ Secret file found")
    else:
        print("❌ Secret file not found")
        return False

    return True

def test_secret_decryption():
    """Test secret decryption"""
    print("\nTesting secret decryption...")

    try:
        from cryptography.fernet import Fernet

        # Generate machine-specific key
        machine_key = hashlib.sha256(f"{platform.node()}{platform.system()}".encode()).digest()
        key = base64.urlsafe_b64encode(machine_key)
        fernet = Fernet(key)

        # Try to decrypt secret
        with open(SECRET_FILE, 'rb') as f:
            encrypted_secret = f.read()

        secret = fernet.decrypt(encrypted_secret).decode()

        if secret and secret != "YOUR_KEYAUTH_SECRET_HERE":
            print("✓ Secret decrypted successfully")
            print(f"  Secret length: {len(secret)} characters")
            return True
        else:
            print("❌ Invalid secret found")
            return False

    except Exception as e:
        print(f"❌ Secret decryption failed: {e}")
        return False

def test_keyauth_initialization():
    """Test KeyAuth initialization with the secret"""
    print("\nTesting KeyAuth initialization...")

    try:
        # Load the secret
        from cryptography.fernet import Fernet

        machine_key = hashlib.sha256(f"{platform.node()}{platform.system()}".encode()).digest()
        key = base64.urlsafe_b64encode(machine_key)
        fernet = Fernet(key)

        with open(SECRET_FILE, 'rb') as f:
            encrypted_secret = f.read()

        secret = fernet.decrypt(encrypted_secret).decode()

        # Test KeyAuth initialization
        from keyauth_integration import initialize_keyauth

        if initialize_keyauth(secret):
            print("✓ KeyAuth initialized successfully")
            return True
        else:
            print("❌ KeyAuth initialization failed")
            return False

    except Exception as e:
        print(f"❌ KeyAuth initialization error: {e}")
        return False

def main():
    """Main test function"""
    print("=" * 60)
    print("KeyAuth Integration Fix Test")
    print("=" * 60)
    
    tests = [
        ("KeyAuth Library Import", test_keyauth_import),
        ("Configuration Files", test_config_files),
        ("Secret Decryption", test_secret_decryption),
        ("KeyAuth Initialization", test_keyauth_initialization),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        result = test_func()
        results.append((test_name, result))
    
    print("\n" + "=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    
    all_passed = True
    for test_name, result in results:
        status = "✓ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
        if not result:
            all_passed = False
    
    if all_passed:
        print("\n🎉 All tests passed! KeyAuth integration is working.")
    else:
        print("\n⚠️  Some tests failed. Check the errors above.")
    
    return all_passed

if __name__ == "__main__":
    try:
        success = main()
        input(f"\nPress Enter to exit...")
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")
        sys.exit(1)
