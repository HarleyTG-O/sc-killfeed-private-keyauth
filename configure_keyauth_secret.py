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
    print("KeyAuth Secret Configuration Tool")
    print("SC Kill Tracker - API Version 1.3")
    print("=" * 60)
    print()
    
    # Ensure config directory exists
    ensure_config_dir()
    
    # Get secret from user
    print("Please enter your KeyAuth application secret:")
    print("(This can be found in your KeyAuth dashboard)")
    print()
    
    secret = input("KeyAuth Secret: ").strip()
    
    # Validate secret
    is_valid, message = validate_secret(secret)
    if not is_valid:
        print(f"❌ Error: {message}")
        return False
    
    print(f"✓ {message}")
    print()
    
    # Try to save with encryption first
    try:
        if CRYPTO_AVAILABLE:
            save_encrypted_secret(secret)
            print("✓ Secret saved with encryption")
        else:
            save_config_secret(secret)
            print("⚠️  Secret saved without encryption (cryptography package not available)")
    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        print("Falling back to config file storage...")
        try:
            save_config_secret(secret)
            print("✓ Secret saved to config file (less secure)")
        except Exception as e2:
            print(f"❌ Failed to save secret: {e2}")
            return False
    
    print()
    print("=" * 60)
    print("Configuration Complete!")
    print("=" * 60)
    print()
    print("Your KeyAuth secret has been configured successfully.")
    print("You can now run your SC Kill Tracker application.")
    print()
    print("Files created/updated:")
    print(f"  - Config: {CONFIG_FILE}")
    if SECRET_FILE.exists():
        print(f"  - Secret: {SECRET_FILE}")
    print()
    print("To reconfigure, run this script again.")
    
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
