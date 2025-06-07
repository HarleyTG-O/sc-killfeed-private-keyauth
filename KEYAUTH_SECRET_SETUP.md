# KeyAuth Secret Configuration Guide

## Problem
The KeyAuth integration for SC Kill Tracker is missing the application secret configuration, which is required for API version 1.3 authentication.

## Quick Fix

### Option 1: Use the Quick Configuration Script (Recommended)

1. **Run the configuration script:**
   ```bash
   python configure_keyauth_secret.py
   ```

2. **Enter your KeyAuth secret when prompted**
   - Get your secret from your KeyAuth dashboard
   - The script will validate and securely store it

3. **Done!** Your application is now configured.

### Option 2: Use the Full Setup Tool

1. **Run the setup tool:**
   ```bash
   python keyauth_setup.py
   ```

2. **Fill in all required fields:**
   - App Name: `SCKillTrac`
   - Owner ID: `EWtg9qJWO2`
   - **Application Secret: [Your KeyAuth Secret]**
   - Version: `1.0`
   - API URL: `https://keyauth.win/api/1.3/`

3. **Click "Save Configuration"**

### Option 3: Manual Configuration

1. **Create/edit the config file:**
   ```
   %LOCALAPPDATA%\Harley's Studio\Star Citizen Kill Tracker\keyauth_config.json
   ```

2. **Add your secret to the config:**
   ```json
   {
     "app_name": "SCKillTrac",
     "owner_id": "EWtg9qJWO2",
     "version": "1.0",
     "api_url": "https://keyauth.win/api/1.3/",
     "app_secret": "YOUR_ACTUAL_KEYAUTH_SECRET_HERE",
     "auto_ban_on_violation": true,
     "session_check_interval": 30
   }
   ```

## Where to Find Your KeyAuth Secret

1. **Log into your KeyAuth dashboard**
2. **Go to your application settings**
3. **Copy the "Application Secret" value**
4. **Use this value in the configuration**

## API Version 1.3 Features

The integration is already configured for KeyAuth API version 1.3, which includes:

- ✅ Enhanced security
- ✅ Improved session management
- ✅ Better error handling
- ✅ HWID blacklisting
- ✅ Real-time session validation
- ✅ Activity logging

## Verification

After configuration, you can verify the setup by:

1. **Running the main application:**
   ```bash
   python keyauth_main.py
   ```

2. **Check the logs for:**
   - "KeyAuth initialized successfully"
   - No "Invalid or missing KeyAuth secret" errors

## Troubleshooting

### "Invalid or missing KeyAuth secret"
- Ensure you've entered the correct secret from your KeyAuth dashboard
- Run the configuration script again
- Check that the secret is at least 10 characters long

### "KeyAuth API failed to initialize"
- Verify your internet connection
- Check that your KeyAuth application is active
- Ensure the API URL is correct: `https://keyauth.win/api/1.3/`

### "Cryptography package not available"
- Install the cryptography package: `pip install cryptography`
- Or use the fallback config file method

## Security Notes

- **Encrypted Storage**: Secrets are encrypted using machine-specific keys
- **Fallback Storage**: If encryption fails, secrets are stored in config files
- **File Permissions**: Ensure config directory has appropriate permissions

## Files Created

After configuration, these files will be created:

```
%LOCALAPPDATA%\Harley's Studio\Star Citizen Kill Tracker\
├── keyauth_config.json          # Main configuration
└── keyauth_secret.enc           # Encrypted secret (if encryption available)
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
