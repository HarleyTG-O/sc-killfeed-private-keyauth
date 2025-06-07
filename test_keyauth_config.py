#!/usr/bin/env python3
"""
KeyAuth Configuration Test Script
Tests the KeyAuth configuration and API connectivity for SC Kill Tracker
"""

import os
import sys
import json
import hashlib
import platform
import base64
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Configuration paths
CONFIG_DIR = Path(os.getenv('LOCALAPPDATA')) / "Harley's Studio" / "Star Citizen Kill Tracker"
CONFIG_FILE = CONFIG_DIR / "keyauth_config.json"
SECRET_FILE = CONFIG_DIR / "keyauth_secret.enc"

def test_config_files():
    """Test if configuration files exist"""
    print("Testing configuration files...")
    
    results = {
        "config_dir": CONFIG_DIR.exists(),
        "config_file": CONFIG_FILE.exists(),
        "secret_file": SECRET_FILE.exists()
    }
    
    print(f"  Config directory: {'✓' if results['config_dir'] else '❌'} {CONFIG_DIR}")
    print(f"  Config file: {'✓' if results['config_file'] else '❌'} {CONFIG_FILE}")
    print(f"  Secret file: {'✓' if results['secret_file'] else '❌'} {SECRET_FILE}")
    
    return results

def load_secret():
    """Load KeyAuth secret using the same method as main app"""
    print("\nTesting secret loading...")
    
    # Try encrypted file first
    if SECRET_FILE.exists() and CRYPTO_AVAILABLE:
        try:
            machine_key = hashlib.sha256(f"{platform.node()}{platform.system()}".encode()).digest()
            key = base64.urlsafe_b64encode(machine_key)
            fernet = Fernet(key)
            
            with open(SECRET_FILE, 'rb') as f:
                encrypted_secret = f.read()
            
            secret = fernet.decrypt(encrypted_secret).decode()
            if secret and secret != "YOUR_KEYAUTH_SECRET_HERE":
                print("  ✓ Secret loaded from encrypted file")
                return secret, "encrypted_file"
        except Exception as e:
            print(f"  ❌ Failed to decrypt secret file: {e}")
    
    # Try config file fallback
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                secret = config.get("app_secret", "")
                if secret and secret != "YOUR_KEYAUTH_SECRET_HERE":
                    print("  ✓ Secret loaded from config file")
                    return secret, "config_file"
        except Exception as e:
            print(f"  ❌ Failed to load from config file: {e}")
    
    print("  ❌ No valid secret found")
    return None, None

def test_keyauth_api(secret):
    """Test KeyAuth API connectivity"""
    print("\nTesting KeyAuth API...")
    
    if not secret:
        print("  ❌ Cannot test API without secret")
        return False
    
    try:
        # Import KeyAuth integration
        from keyauth_integration import KeyAuthAPI
        
        # Create API instance
        api = KeyAuthAPI(
            name="SCKillTrac",
            ownerid="EWtg9qJWO2",
            secret=secret,
            version="1.0",
            api_url="https://keyauth.win/api/1.3/"
        )
        
        if api.initialized:
            print("  ✓ KeyAuth API initialized successfully")
            
            # Test session check
            if api.check_session():
                print("  ✓ Session validation working")
            else:
                print("  ⚠️  Session validation failed (may be normal)")
            
            return True
        else:
            print("  ❌ KeyAuth API failed to initialize")
            return False
            
    except Exception as e:
        print(f"  ❌ API test failed: {e}")
        return False

def test_imports():
    """Test required imports"""
    print("\nTesting imports...")
    
    imports = {
        "keyauth_integration": False,
        "keyauth_dialogs": False,
        "keyauth_main": False,
        "protection": False,
        "cryptography": CRYPTO_AVAILABLE
    }
    
    # Test KeyAuth modules
    try:
        import keyauth_integration
        imports["keyauth_integration"] = True
    except ImportError as e:
        print(f"  ❌ keyauth_integration: {e}")
    
    try:
        import keyauth_dialogs
        imports["keyauth_dialogs"] = True
    except ImportError as e:
        print(f"  ❌ keyauth_dialogs: {e}")
    
    try:
        import keyauth_main
        imports["keyauth_main"] = True
    except ImportError as e:
        print(f"  ❌ keyauth_main: {e}")
    
    try:
        import protection
        imports["protection"] = True
    except ImportError as e:
        print(f"  ❌ protection: {e}")
    
    # Print results
    for module, status in imports.items():
        print(f"  {module}: {'✓' if status else '❌'}")
    
    return imports

def main():
    """Main test function"""
    print("=" * 60)
    print("KeyAuth Configuration Test")
    print("SC Kill Tracker - API Version 1.3")
    print("=" * 60)
    
    # Test configuration files
    config_results = test_config_files()
    
    # Test imports
    import_results = test_imports()
    
    # Test secret loading
    secret, source = load_secret()
    
    # Test API if secret is available
    api_working = False
    if secret:
        api_working = test_keyauth_api(secret)
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    all_good = True
    
    if not config_results["config_file"]:
        print("❌ Configuration file missing - run configure_keyauth_secret.py")
        all_good = False
    
    if not secret:
        print("❌ KeyAuth secret not configured - run configure_keyauth_secret.py")
        all_good = False
    
    if not import_results["keyauth_integration"]:
        print("❌ KeyAuth integration module missing")
        all_good = False
    
    if not import_results["cryptography"]:
        print("⚠️  Cryptography package not available - install with: pip install cryptography")
    
    if secret and not api_working:
        print("❌ KeyAuth API not working - check your secret and internet connection")
        all_good = False
    
    if all_good:
        print("✅ All tests passed! KeyAuth is properly configured.")
        print(f"   Secret source: {source}")
        print("   Ready to run SC Kill Tracker with KeyAuth authentication.")
    else:
        print("❌ Some tests failed. Please fix the issues above.")
    
    print("\nNext steps:")
    if not secret:
        print("  1. Run: python configure_keyauth_secret.py")
    if all_good:
        print("  1. Run: python keyauth_main.py")
    print("  2. Test authentication with your KeyAuth credentials")
    
    return all_good

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
        input("\nPress Enter to exit...")
        sys.exit(1)
