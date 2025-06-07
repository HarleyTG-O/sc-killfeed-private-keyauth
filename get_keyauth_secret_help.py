#!/usr/bin/env python3
"""
KeyAuth Secret Help Guide
Explains where to find your KeyAuth application secret
"""

def main():
    print("=" * 70)
    print("KeyAuth Application Secret - Where to Find It")
    print("=" * 70)
    print()
    
    print("🔐 Your KeyAuth application secret is required for initialization.")
    print("   This is NOT your username or password - it's your app secret.")
    print()
    
    print("📍 Where to find your KeyAuth application secret:")
    print()
    print("1. 🌐 Go to https://keyauth.win/")
    print("2. 🔑 Log into your KeyAuth account")
    print("3. 📱 Go to your Applications dashboard")
    print("4. ⚙️  Click on your application (SCKillTrac)")
    print("5. 📋 Look for 'Application Secret' or 'App Secret'")
    print("6. 📄 Copy the LONG secret string (not the short owner ID)")
    print()
    
    print("🔍 What it looks like:")
    print("   ✅ Application Secret: Long string (50+ characters)")
    print("   ❌ Owner ID: Short string (EWtg9qJWO2) - this is NOT the secret")
    print("   ❌ Username: Your account name - this is NOT the secret")
    print()
    
    print("⚠️  Important Notes:")
    print("   • The secret is case-sensitive")
    print("   • Copy the entire secret (no spaces at beginning/end)")
    print("   • This secret is unique to your application")
    print("   • Keep it secure - don't share it publicly")
    print()
    
    print("🛠️  Once you have your secret:")
    print("   1. Run: python configure_keyauth_secret.py")
    print("   2. Paste your application secret when prompted")
    print("   3. The secret will be encrypted and stored securely")
    print("   4. Your application will initialize successfully")
    print()
    
    print("❓ Still having trouble?")
    print("   • Make sure you're logged into the correct KeyAuth account")
    print("   • Verify you're looking at the right application")
    print("   • Check that your application is active/enabled")
    print("   • Contact KeyAuth support if you can't find the secret")
    print()
    
    print("🎯 Expected result after configuration:")
    print("   ✅ 'KeyAuth initialized successfully'")
    print("   ✅ No more 'Invalid Application Information' errors")
    print("   ✅ Users can authenticate with KeyAuth credentials")
    print()
    
    print("=" * 70)
    print("Ready to configure? Run: python configure_keyauth_secret.py")
    print("=" * 70)

if __name__ == "__main__":
    try:
        main()
        input("\nPress Enter to exit...")
    except KeyboardInterrupt:
        print("\n\nExiting...")
    except Exception as e:
        print(f"\nError: {e}")
        input("\nPress Enter to exit...")
