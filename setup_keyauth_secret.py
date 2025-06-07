#!/usr/bin/env python3
"""
KeyAuth Secret Setup Tool
Simple tool to configure your KeyAuth application secret
"""

import os
import json
import sys
import hashlib
import platform
import base64
from pathlib import Path
from cryptography.fernet import Fernet
import getpass

# Configuration paths
CONFIG_DIR = Path(os.getenv('LOCALAPPDATA')) / "Harley's Studio" / "Star Citizen Kill Tracker"
CONFIG_FILE = CONFIG_DIR / "keyauth_config.json"
SECRET_FILE = CONFIG_DIR / "keyauth_secret.enc"

def generate_machine_key():
    """Generate encryption key from machine-specific data"""
    machine_key = hashlib.sha256(f"{platform.node()}{platform.system()}".encode()).digest()
    return base64.urlsafe_b64encode(machine_key)

def encrypt_secret(secret: str, key: bytes) -> bytes:
    """Encrypt the secret"""
    fernet = Fernet(key)
    return fernet.encrypt(secret.encode())

def save_secret(secret: str):
    """Save the encrypted secret"""
    try:
        # Ensure directory exists
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        # Generate machine-specific encryption key
        key = generate_machine_key()

        # Encrypt the secret
        encrypted_secret = encrypt_secret(secret, key)

        # Save encrypted secret
        with open(SECRET_FILE, 'wb') as f:
            f.write(encrypted_secret)

        print(f"✓ Secret saved to: {SECRET_FILE}")
        return True

    except Exception as e:
        print(f"❌ Failed to save secret: {e}")
        return False

def create_config():
    """Create basic configuration file"""
    try:
        config = {
            "app_name": "SCKillTrac",
            "owner_id": "EWtg9qJWO2",
            "version": "1.0",
            "api_url": "https://keyauth.win/api/1.3/",
            "auto_ban_on_violation": True,
            "session_check_interval": 30
        }
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        
        print(f"✓ Configuration saved to: {CONFIG_FILE}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to save configuration: {e}")
        return False

def main():
    """Main setup function"""
    print("=" * 60)
    print("KeyAuth Secret Setup Tool")
    print("SC Kill Tracker - KeyAuth Integration")
    print("=" * 60)
    print()
    
    print("This tool will help you configure your KeyAuth application secret.")
    print("You need to get your application secret from your KeyAuth dashboard.")
    print()
    
    # Get the secret from user
    secret = getpass.getpass("Enter your KeyAuth application secret: ").strip()
    
    if not secret:
        print("❌ No secret provided. Setup cancelled.")
        return False
    
    if secret == "YOUR_KEYAUTH_SECRET_HERE":
        print("❌ Please enter your actual KeyAuth secret, not the placeholder.")
        return False
    
    print("\nSaving configuration...")
    
    # Create configuration
    if not create_config():
        return False
    
    # Save secret
    if not save_secret(secret):
        return False
    
    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)
    print()
    print("✅ KeyAuth secret has been configured successfully!")
    print("✅ Configuration files created")
    print()
    print("Next steps:")
    print("  1. Test your configuration: python test_keyauth_config.py")
    print("  2. Run your application: python SCKillTrac[Global].py")
    print()
    print("Files created:")
    print(f"  - {CONFIG_FILE}")
    print(f"  - {SECRET_FILE}")
    print("  (Secret is encrypted using machine-specific key)")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        input(f"\nPress Enter to exit...")
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        input("\nPress Enter to exit...")
        sys.exit(1)
