#!/usr/bin/env python3
"""
Quick KeyAuth Secret Configuration Tool
Simple script to configure your KeyAuth application secret for SC Kill Tracker
"""

import os
import json
import hashlib
import platform
import base64
from pathlib import Path

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography package not available. Secret will be stored in plain text.")

# Configuration paths
CONFIG_DIR = Path(os.getenv('LOCALAPPDATA')) / "Harley's Studio" / "Star Citizen Kill Tracker"
CONFIG_FILE = CONFIG_DIR / "keyauth_config.json"
SECRET_FILE = CONFIG_DIR / "keyauth_secret.enc"

def ensure_config_dir():
    """Ensure configuration directory exists"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

def save_encrypted_secret(secret):
    """Save secret using encryption"""
    if not CRYPTO_AVAILABLE:
        raise Exception("Cryptography package not available")
    
    # Generate key from machine-specific data
    machine_key = hashlib.sha256(f"{platform.node()}{platform.system()}".encode()).digest()
    key = base64.urlsafe_b64encode(machine_key)
    fernet = Fernet(key)
    
    # Encrypt and save
    encrypted_secret = fernet.encrypt(secret.encode())
    with open(SECRET_FILE, 'wb') as f:
        f.write(encrypted_secret)
    
    print(f"✓ Secret encrypted and saved to: {SECRET_FILE}")

def save_config_secret(secret):
    """Save secret in config file (fallback method)"""
    # Load existing config or create new
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    else:
        config = {
            "app_name": "SCKillTrac",
            "owner_id": "EWtg9qJWO2",
            "version": "1.0",
            "api_url": "https://keyauth.win/api/1.3/",
            "auto_ban_on_violation": True,
            "session_check_interval": 30
        }
    
    # Add secret to config
    config["app_secret"] = secret
    
    # Save config
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)
    
    print(f"✓ Secret saved to config file: {CONFIG_FILE}")

def validate_secret(secret):
    """Validate the provided secret"""
    if not secret:
        return False, "Secret cannot be empty"
    
    if len(secret) < 10:
        return False, "Secret must be at least 10 characters long"
    
    if secret == "YOUR_KEYAUTH_SECRET_HERE":
        return False, "Please provide your actual KeyAuth secret"
    
    return True, "Secret is valid"

def main():
    """Main configuration function"""
    print("=" * 60)
    print("KeyAuth Library Configuration")
    print("SC Kill Tracker - Using Official KeyAuth Library")
    print("=" * 60)
    print()

    print("✅ Good news! The KeyAuth integration now uses the official library.")
    print("✅ No application secret configuration is required!")
    print()
    print("The KeyAuth library handles authentication automatically using:")
    print("  - App Name: SCKillTrac")
    print("  - Owner ID: EWtg9qJWO2")
    print("  - Version: 1.0")
    print("  - File Hash: Automatically calculated")
    print()

    # Ensure config directory exists
    ensure_config_dir()

    # Create basic config file
    try:
        config = {
            "app_name": "SCKillTrac",
            "owner_id": "EWtg9qJWO2",
            "version": "1.0",
            "api_url": "https://keyauth.win/api/1.3/",
            "auto_ban_on_violation": True,
            "session_check_interval": 30,
            "library_mode": True
        }

        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)

        print("✓ Configuration file created")

    except Exception as e:
        print(f"❌ Failed to create config: {e}")
        return False

    print()
    print("=" * 60)
    print("Configuration Complete!")
    print("=" * 60)
    print()
    print("Your KeyAuth integration is ready to use!")
    print("The application will authenticate users directly through KeyAuth.")
    print()
    print("Files created/updated:")
    print(f"  - Config: {CONFIG_FILE}")
    print()
    print("Next steps:")
    print("  1. Install KeyAuth library: pip install keyauth")
    print("  2. Run your SC Kill Tracker application")
    print("  3. Users can login with their KeyAuth credentials")

    return True

if __name__ == "__main__":
    try:
        success = main()
        if not success:
            input("\nPress Enter to exit...")
            exit(1)
        else:
            input("\nPress Enter to exit...")
    except KeyboardInterrupt:
        print("\n\nConfiguration cancelled by user.")
        exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        input("\nPress Enter to exit...")
        exit(1)
