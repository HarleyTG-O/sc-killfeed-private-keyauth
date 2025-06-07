# KeyAuth Integration for SC Kill Tracker

This document describes the complete KeyAuth integration for SC Kill Tracker, providing secure authentication, user management, and HWID banning capabilities.

## 🚀 Features

### Authentication & Security
- **Secure Login/Register**: Username/password authentication with KeyAuth
- **License Key Authentication**: Direct license key login support
- **2FA Support**: Two-factor authentication integration
- **HWID Tracking**: Hardware ID-based user identification
- **Session Management**: Secure session validation and monitoring
- **Blacklist Protection**: Automatic HWID and IP blacklisting

### User Management
- **Real-time User Monitoring**: Track online users and activity
- **Remote User Banning**: Ban users instantly with reason logging
- **HWID Blacklisting**: Permanent hardware-based bans
- **User Variables**: Store custom data per user
- **Activity Logging**: Comprehensive user action logging

### Protection System
- **Anti-Debug**: Advanced debugger detection
- **File Integrity**: Real-time file modification detection
- **VM/Sandbox Detection**: Virtual environment identification
- **Anti-Tamper**: Code modification protection
- **Automatic Banning**: Auto-ban on protection violations

### Admin Features
- **Admin Panel**: Full-featured GUI for user management
- **License Generation**: Create and manage license keys
- **Real-time Monitoring**: Live user activity monitoring
- **Webhook Integration**: Discord notifications for events
- **Bulk Operations**: Mass user management capabilities

## 📁 File Structure

```
keyauth_integration.py     # Core KeyAuth API integration
keyauth_dialogs.py         # Modern Qt authentication dialogs
keyauth_admin.py          # Admin panel for user management
keyauth_main.py           # Main application entry point
keyauth_setup.py          # Configuration and setup tool
protection.py             # Enhanced protection system (modified)
requirements_keyauth.txt  # Python dependencies
```

## 🛠️ Installation

### 1. Install Dependencies

```bash
pip install -r requirements_keyauth.txt
```

### 2. Configure KeyAuth

Run the setup tool to configure your KeyAuth application:

```bash
python keyauth_setup.py
```

Enter your KeyAuth application details:
- **App Name**: Your KeyAuth application name
- **Owner ID**: Your KeyAuth account ID
- **App Secret**: Your KeyAuth application secret
- **Seller Key**: Your KeyAuth seller key (for admin functions)

### 3. Update Configuration

Edit the configuration in `keyauth_main.py`:

```python
# Replace with your actual KeyAuth secret
def load_keyauth_secret(self):
    return "YOUR_KEYAUTH_SECRET_HERE"
```

## 🚀 Usage

### Basic Authentication

```python
from keyauth_integration import initialize_keyauth, get_keyauth_manager
from keyauth_dialogs import show_auth_dialog

# Initialize KeyAuth
if initialize_keyauth("your_secret_here"):
    # Show authentication dialog
    if show_auth_dialog():
        manager = get_keyauth_manager()
        user_info = manager.get_user_info()
        print(f"Welcome {user_info['username']}!")
```

### User Management

```python
from keyauth_integration import get_keyauth_manager

manager = get_keyauth_manager()

# Ban current user
manager.ban_current_user("Violation detected")

# Check if session is valid
if manager.is_session_valid():
    print("User is authenticated")

# Log activity
manager.api.log_activity("User performed action")
```

### Admin Operations

```python
from keyauth_admin import KeyAuthAdminPanel

# Open admin panel
admin_panel = KeyAuthAdminPanel("your_seller_key")
admin_panel.run()
```

## 🔧 Configuration Options

### KeyAuth Settings
- `app_name`: Your KeyAuth application name
- `owner_id`: Your KeyAuth account ID
- `version`: Application version for updates
- `api_url`: KeyAuth API endpoint

### Security Settings
- `auto_ban_on_violation`: Auto-ban users on protection violations
- `hwid_tracking`: Enable hardware ID tracking
- `session_monitoring`: Enable session validation
- `session_check_interval`: How often to validate sessions (seconds)

### Protection Settings
- `webhook_url`: Discord webhook for notifications
- `check_interval`: Protection system check frequency
- `debug_detection`: Enable anti-debug protection
- `file_integrity`: Enable file integrity monitoring

## 🛡️ Protection Features

### Anti-Debug Protection
- Detects common debuggers (x64dbg, OllyDbg, etc.)
- Multiple detection methods
- Escalating response system
- Automatic user banning on repeated attempts

### File Integrity Monitoring
- Real-time file hash verification
- Detects code modifications
- Protects critical application files
- Immediate response to tampering

### HWID-Based Security
- Unique hardware fingerprinting
- Cross-platform HWID generation
- Blacklist enforcement
- Hardware-based user tracking

## 📊 Admin Panel Features

### User Management
- View all registered users
- Real-time online user monitoring
- Ban/unban users with reasons
- View user details and activity

### HWID Management
- View blacklisted hardware IDs
- Add/remove HWIDs from blacklist
- Bulk HWID operations
- Hardware-based user tracking

### License Management
- Generate license keys
- Set license duration and format
- Bulk license creation
- License usage tracking

### Activity Monitoring
- Real-time activity logs
- User action tracking
- Security event monitoring
- Export logs for analysis

## 🔗 Integration with Existing Code

### Replace Current Authentication

Replace your existing registration dialog with KeyAuth:

```python
# Old code
if not user_registered():
    registration_dialog = RegistrationDialog()
    if registration_dialog.exec() != QDialog.Accepted:
        sys.exit(0)

# New KeyAuth code
if not show_auth_dialog():
    sys.exit(0)
```

### Add Protection Integration

```python
from protection import AdvancedProtection

# Initialize protection with KeyAuth integration
protection = AdvancedProtection(
    app_name="SCKillTrac[Global]",
    webhook_url="your_discord_webhook"
)
protection.start_protection_thread()
```

## 🚨 Security Best Practices

### Secret Management
- Never hardcode secrets in source code
- Use environment variables or encrypted storage
- Rotate secrets regularly
- Limit access to sensitive configuration

### HWID Handling
- Validate HWID format before processing
- Log all HWID-related operations
- Implement HWID change detection
- Use secure HWID generation methods

### Session Security
- Validate sessions regularly
- Implement session timeouts
- Log all authentication events
- Monitor for suspicious activity

## 🐛 Troubleshooting

### Common Issues

**"KeyAuth not initialized"**
- Check your application secret
- Verify network connectivity
- Ensure KeyAuth application is active

**"HWID blacklisted"**
- Check admin panel for blacklist status
- Verify HWID generation is working
- Contact admin to remove from blacklist

**"Session invalid"**
- Re-authenticate the user
- Check session timeout settings
- Verify KeyAuth server status

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📞 Support

For KeyAuth-specific issues:
- Visit: https://keyauth.cc
- Discord: https://discord.gg/keyauth
- Documentation: https://docs.keyauth.cc

For SC Kill Tracker integration issues:
- Check the logs in `%LOCALAPPDATA%\Harley's Studio\Star Citizen Kill Tracker\`
- Use the setup tool to validate configuration
- Test connection using the admin panel

## 📄 License

This KeyAuth integration follows the same license as SC Kill Tracker. KeyAuth itself is licensed under Elastic License 2.0.

## 🔄 Updates

To update the KeyAuth integration:
1. Pull latest changes
2. Update dependencies: `pip install -r requirements_keyauth.txt --upgrade`
3. Run setup tool to verify configuration
4. Test authentication and admin functions

---

**Note**: Replace all placeholder values (secrets, webhooks, etc.) with your actual KeyAuth application details before deployment.
