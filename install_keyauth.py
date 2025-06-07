#!/usr/bin/env python3
"""
KeyAuth Library Installation Script
Installs the official KeyAuth Python library for SC Kill Tracker
"""

import subprocess
import sys
import os

def install_package(package_name):
    """Install a package using pip"""
    try:
        print(f"Installing {package_name}...")
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", package_name
        ], capture_output=True, text=True, check=True)
        
        print(f"✓ {package_name} installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install {package_name}")
        print(f"Error: {e.stderr}")
        return False

def check_package(package_name):
    """Check if a package is already installed"""
    try:
        __import__(package_name)
        return True
    except ImportError:
        return False

def main():
    """Main installation function"""
    print("=" * 60)
    print("KeyAuth Library Installation")
    print("SC Kill Tracker - Official KeyAuth Integration")
    print("=" * 60)
    print()
    
    packages_to_install = [
        ("keyauth", "KeyAuth official library"),
        ("requests", "HTTP requests library"),
        ("cryptography", "Encryption library")
    ]
    
    all_installed = True
    
    for package, description in packages_to_install:
        print(f"Checking {description}...")
        
        if check_package(package):
            print(f"✓ {package} is already installed")
        else:
            print(f"⚠️  {package} not found, installing...")
            if not install_package(package):
                all_installed = False
        print()
    
    if all_installed:
        print("=" * 60)
        print("Installation Complete!")
        print("=" * 60)
        print()
        print("✅ All required packages are installed.")
        print("✅ KeyAuth integration is ready to use!")
        print()
        print("Next steps:")
        print("  1. Run: python configure_keyauth_secret.py")
        print("  2. Run: python test_keyauth_config.py")
        print("  3. Start your SC Kill Tracker application")
        print()
        print("Your KeyAuth integration uses:")
        print("  - App Name: SCKillTrac")
        print("  - Owner ID: EWtg9qJWO2")
        print("  - Version: 1.0")
        print("  - No application secret required!")
        
    else:
        print("=" * 60)
        print("Installation Issues")
        print("=" * 60)
        print()
        print("❌ Some packages failed to install.")
        print("Please try installing manually:")
        print()
        for package, description in packages_to_install:
            if not check_package(package):
                print(f"  pip install {package}")
        print()
        print("Or install all at once:")
        print("  pip install keyauth requests cryptography")
    
    return all_installed

if __name__ == "__main__":
    try:
        success = main()
        input(f"\nPress Enter to exit...")
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nInstallation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        input("\nPress Enter to exit...")
        sys.exit(1)
