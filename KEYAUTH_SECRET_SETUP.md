# KeyAuth Library Setup Guide

## KeyAuth Integration 🔐
The KeyAuth integration uses the **official KeyAuth Python library** with your application secret.

## Quick Setup

### Step 1: Install KeyAuth Library

**Automatic Installation (Recommended):**
```bash
python install_keyauth.py
```

**Manual Installation:**
```bash
pip install keyauth
```

### Step 2: Configure Your Secret (Required)

```bash
python configure_keyauth_secret.py
```

Enter your KeyAuth application secret when prompted.

### Step 3: Test Setup

```bash
python test_keyauth_config.py
```

## How It Works

The integration uses the official KeyAuth library with these settings:

```python
keyauthapp = Keyauth(
    name="SCKillTrac",          # App name
    owner_id="EWtg9qJWO2",      # Account ID
    secret="YOUR_APP_SECRET",   # Application secret (required)
    version="1.0",              # Application version
    file_hash=getchecksum()     # File hash (automatic)
)
```

**Application secret is required** for proper authentication and initialization.

## User Authentication

Users can authenticate using:
- **Username & Password** - Standard KeyAuth login
- **License Key** - Direct license authentication
- **Registration** - New user registration with license

## Integration with SC Kill Tracker

✅ **User ID Files**: KeyAuth users get encrypted ID files (same as local users)
✅ **Session Management**: Automatic session validation and monitoring
✅ **HWID Tracking**: Hardware-based user identification
✅ **Activity Logging**: All actions logged to KeyAuth dashboard

## Library Features

The official KeyAuth library provides:

- ✅ **No Secrets Required** - Library handles authentication automatically
- ✅ **Automatic HWID** - Hardware ID generation and tracking
- ✅ **Session Management** - Built-in session validation
- ✅ **Error Handling** - Comprehensive error messages
- ✅ **Activity Logging** - All actions logged to dashboard
- ✅ **Blacklist Support** - HWID blacklisting capabilities

## Verification

After setup, verify everything works:

1. **Test the configuration:**
   ```bash
   python test_keyauth_config.py
   ```

2. **Run your application:**
   ```bash
   python SCKillTrac[Global].py
   ```

3. **Check for successful initialization:**
   - "KeyAuth integration loaded successfully"
   - "KeyAuth initialized successfully"

## Troubleshooting

### "KeyAuth library not found"
```bash
pip install keyauth
```

### "KeyAuth integration not available"
- Check that `keyauth_integration.py` exists
- Verify all imports are working
- Run the test script for detailed diagnostics

### "KeyAuth initialization failed"
- Check your internet connection
- Verify the app name and owner ID are correct
- Ensure your KeyAuth application is active

## Files Created

After setup, these files will be created:

```
%LOCALAPPDATA%\Harley's Studio\Star Citizen Kill Tracker\
├── keyauth_config.json          # Basic configuration
└── User\
    └── [username]_id.enc        # Encrypted user ID files (for each KeyAuth user)
```

## Support

If you continue to have issues:

1. **Check the logs** for detailed error messages
2. **Verify your KeyAuth dashboard** settings
3. **Ensure API version 1.3** is supported by your KeyAuth plan
4. **Contact support** with the specific error messages

## Next Steps

Once configured:

1. **Test authentication** with the main application
2. **Verify user login/registration** works
3. **Check session monitoring** is active
4. **Test protection features** if enabled

---

**Note**: This configuration is required for KeyAuth API version 1.3. The integration includes all necessary features for secure authentication and user management.
