"""
Integration Script for Adding KeyAuth to Existing SC Kill Tracker
This script helps integrate KeyAuth into your existing SCKillTrac[Global].py
"""

import os
import shutil
import sys
from pathlib import Path

def backup_original_files():
    """Create backup of original files"""
    print("Creating backup of original files...")
    
    files_to_backup = [
        "SCKillTrac[Global].py",
        "protection.py"
    ]
    
    backup_dir = Path("backup_original")
    backup_dir.mkdir(exist_ok=True)
    
    for file in files_to_backup:
        if Path(file).exists():
            shutil.copy2(file, backup_dir / file)
            print(f"✓ Backed up {file}")
        else:
            print(f"⚠ Warning: {file} not found")
    
    print(f"Backup created in: {backup_dir.absolute()}")

def create_integration_guide():
    """Create step-by-step integration guide"""
    guide = """
# KeyAuth Integration Guide for SC Kill Tracker

## Step 1: Backup Complete ✓
Your original files have been backed up to the 'backup_original' folder.

## Step 2: Install Dependencies
Run the following command to install required packages:
```
pip install -r requirements_keyauth.txt
```

## Step 3: Configure KeyAuth
1. Run the setup tool:
   ```
   python keyauth_setup.py
   ```
2. Enter your KeyAuth application details:
   - App Name: SCKillTrac
   - Owner ID: EWtg9qJWO2
   - App Secret: [Your KeyAuth Secret]
   - Seller Key: [Your Seller Key for Admin]

## Step 4: Update Main Application
Replace the authentication section in your main file with KeyAuth integration:

### Original Code (to replace):
```python
if not user_registered():
    registration_dialog = RegistrationDialog()
    if registration_dialog.exec() != QDialog.Accepted:
        qt_app.quit()
        sys.exit(0)
```

### New KeyAuth Code:
```python
from keyauth_dialogs import show_auth_dialog
from keyauth_integration import get_keyauth_manager

if not show_auth_dialog():
    qt_app.quit()
    sys.exit(0)

# Get authenticated user info
manager = get_keyauth_manager()
user_data = manager.get_user_info()
```

## Step 5: Add Protection Integration
Add this to your main initialization:

```python
from protection import AdvancedProtection

# Initialize enhanced protection with KeyAuth
protection = AdvancedProtection(
    app_name="SCKillTrac[Global]-KeyAuth",
    webhook_url="YOUR_DISCORD_WEBHOOK_URL"
)
protection.start_protection_thread()
```

## Step 6: Update User Data Handling
Replace local user data with KeyAuth user data:

### Old:
```python
user_data = load_first_user_data(key)
```

### New:
```python
manager = get_keyauth_manager()
user_data = {
    "Username": manager.user_data.get("username"),
    "SCKillTrac ID": f"{manager.user_data.get('username')}@SCKillTrac-KeyAuth",
    "UUID": manager.user_data.get("hwid"),
    "HWID": manager.user_data.get("hwid"),
    "IP": manager.user_data.get("ip"),
    "Subscription": manager.user_data.get("subscription")
}
```

## Step 7: Add Session Monitoring
Add session validation to your main loop:

```python
def check_auth_status():
    manager = get_keyauth_manager()
    if manager and not manager.is_session_valid():
        QMessageBox.critical(None, "Session Expired", "Your session has expired. Please restart the application.")
        sys.exit(0)

# Call this periodically or on important actions
```

## Step 8: Admin Panel Access
To access the admin panel for user management:

```python
python keyauth_admin.py
```

Or integrate it into your application:
```python
from keyauth_admin import KeyAuthAdminPanel

def open_admin_panel():
    admin_panel = KeyAuthAdminPanel("your_seller_key")
    admin_panel.run()
```

## Step 9: Testing
1. Run the setup tool to verify configuration
2. Test authentication with the new system
3. Verify protection features are working
4. Test admin panel functionality

## Step 10: Deployment
1. Update your build scripts to include KeyAuth files
2. Ensure all dependencies are included
3. Test on clean system
4. Update documentation for users

## Important Notes:
- Keep your KeyAuth secrets secure
- Test thoroughly before deploying
- Monitor logs for any issues
- Set up Discord webhooks for notifications

## Files Added:
- keyauth_integration.py - Core KeyAuth functionality
- keyauth_dialogs.py - Authentication UI
- keyauth_admin.py - Admin panel
- keyauth_setup.py - Configuration tool
- keyauth_main.py - Example main entry point
- protection.py - Enhanced (modified original)

## Rollback Instructions:
If you need to rollback to the original system:
1. Copy files from backup_original/ back to main directory
2. Remove KeyAuth files
3. Uninstall KeyAuth dependencies if desired

For support, refer to KEYAUTH_README.md or contact support.
"""
    
    with open("INTEGRATION_GUIDE.md", "w") as f:
        f.write(guide)
    
    print("✓ Integration guide created: INTEGRATION_GUIDE.md")

def check_dependencies():
    """Check if required dependencies are available"""
    print("\nChecking dependencies...")
    
    required_modules = [
        "requests",
        "cryptography", 
        "PySide6",
        "psutil"
    ]
    
    missing = []
    for module in required_modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except ImportError:
            print(f"✗ {module} (missing)")
            missing.append(module)
    
    if missing:
        print(f"\n⚠ Missing dependencies: {', '.join(missing)}")
        print("Run: pip install -r requirements_keyauth.txt")
    else:
        print("\n✓ All dependencies available")

def verify_keyauth_files():
    """Verify KeyAuth integration files are present"""
    print("\nVerifying KeyAuth files...")
    
    required_files = [
        "keyauth_integration.py",
        "keyauth_dialogs.py", 
        "keyauth_admin.py",
        "keyauth_setup.py",
        "requirements_keyauth.txt",
        "KEYAUTH_README.md"
    ]
    
    missing = []
    for file in required_files:
        if Path(file).exists():
            print(f"✓ {file}")
        else:
            print(f"✗ {file} (missing)")
            missing.append(file)
    
    if missing:
        print(f"\n⚠ Missing files: {', '.join(missing)}")
        print("Please ensure all KeyAuth files are in the same directory")
    else:
        print("\n✓ All KeyAuth files present")

def main():
    """Main integration process"""
    print("=" * 60)
    print("SC Kill Tracker - KeyAuth Integration Script")
    print("=" * 60)
    
    # Check current directory
    if not Path("SCKillTrac[Global].py").exists():
        print("⚠ Warning: SCKillTrac[Global].py not found in current directory")
        print("Please run this script from your SC Kill Tracker directory")
        input("Press Enter to continue anyway...")
    
    # Verify KeyAuth files
    verify_keyauth_files()
    
    # Check dependencies
    check_dependencies()
    
    # Create backup
    backup_original_files()
    
    # Create integration guide
    create_integration_guide()
    
    print("\n" + "=" * 60)
    print("Integration Preparation Complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Read INTEGRATION_GUIDE.md for detailed instructions")
    print("2. Install dependencies: pip install -r requirements_keyauth.txt")
    print("3. Run setup tool: python keyauth_setup.py")
    print("4. Follow the integration guide to modify your code")
    print("5. Test the new authentication system")
    print("\nFor detailed documentation, see KEYAUTH_README.md")
    print("\nBackup of original files: backup_original/")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
