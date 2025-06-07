"""
KeyAuth-Integrated Main Entry Point for SC Kill Tracker
Replaces the existing authentication system with full KeyAuth integration
"""

import sys
import os
import logging
import json
import hashlib
import platform
from pathlib import Path
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import Qt

# Import existing SC Kill Tracker modules
try:
    from SCKillTrac import *  # Import all existing functionality
except ImportError:
    # Fallback imports
    import SCKillTrac as SCKT

# Import KeyAuth integration
from keyauth_integration import initialize_keyauth, get_keyauth_manager
from keyauth_dialogs import show_auth_dialog
from protection import AdvancedProtection

# Configuration
KEYAUTH_CONFIG_FILE = Path(os.getenv('LOCALAPPDATA')) / "Harley's Studio" / "Star Citizen Kill Tracker" / "keyauth_config.json"
KEYAUTH_SECRET_FILE = Path(os.getenv('LOCALAPPDATA')) / "Harley's Studio" / "Star Citizen Kill Tracker" / "keyauth_secret.enc"

class KeyAuthSCKillTracker:
    """Main application class with KeyAuth integration"""
    
    def __init__(self):
        self.app = None
        self.keyauth_manager = None
        self.protection_system = None
        self.user_data = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger("KeyAuthSCKT")
    
    def initialize_application(self):
        """Initialize the application with KeyAuth"""
        try:
            # Create Qt application
            self.app = QApplication(sys.argv)
            self.app.setApplicationName("SC Kill Tracker")
            self.app.setApplicationVersion("v0.1.3.6.4-KeyAuth")
            
            # Load KeyAuth configuration
            if not self.load_keyauth_config():
                self.logger.error("Failed to load KeyAuth configuration")
                return False
            
            # Initialize protection system
            self.initialize_protection()
            
            # Show authentication dialog
            if not self.authenticate_user():
                self.logger.info("Authentication cancelled or failed")
                return False
            
            # Verify session and start monitoring
            self.start_session_monitoring()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Application initialization failed: {e}")
            return False
    
    def load_keyauth_config(self):
        """Load KeyAuth configuration"""
        try:
            # Ensure config directory exists
            KEYAUTH_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            
            # Load or create configuration
            if KEYAUTH_CONFIG_FILE.exists():
                with open(KEYAUTH_CONFIG_FILE, 'r') as f:
                    config = json.load(f)
            else:
                # Default configuration
                config = {
                    "app_name": "SCKillTrac",
                    "owner_id": "EWtg9qJWO2",
                    "version": "1.0",
                    "api_url": "https://keyauth.win/api/1.3/",
                    "auto_ban_on_violation": True,
                    "session_check_interval": 30
                }
                
                # Save default config
                with open(KEYAUTH_CONFIG_FILE, 'w') as f:
                    json.dump(config, f, indent=4)
            
            # Load secret (you'll need to set this)
            secret = self.load_keyauth_secret()
            if not secret:
                QMessageBox.critical(None, "Configuration Error", 
                                   "KeyAuth secret not configured. Please contact support.")
                return False
            
            # Initialize KeyAuth
            return initialize_keyauth(secret)
            
        except Exception as e:
            self.logger.error(f"Failed to load KeyAuth config: {e}")
            return False
    
    def load_keyauth_secret(self):
        """Load KeyAuth secret from secure storage"""
        try:
            # Try to load from encrypted file first
            if KEYAUTH_SECRET_FILE.exists():
                try:
                    from cryptography.fernet import Fernet
                    import base64

                    # Generate key from machine-specific data
                    machine_key = hashlib.sha256(f"{platform.node()}{platform.system()}".encode()).digest()
                    key = base64.urlsafe_b64encode(machine_key)
                    fernet = Fernet(key)

                    with open(KEYAUTH_SECRET_FILE, 'rb') as f:
                        encrypted_secret = f.read()

                    secret = fernet.decrypt(encrypted_secret).decode()
                    if secret and secret != "YOUR_KEYAUTH_SECRET_HERE":
                        return secret

                except Exception as e:
                    self.logger.warning(f"Failed to decrypt secret file: {e}")

            # Try to load from config file as fallback
            if KEYAUTH_CONFIG_FILE.exists():
                with open(KEYAUTH_CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    secret = config.get("app_secret", "")
                    if secret and secret != "YOUR_KEYAUTH_SECRET_HERE":
                        return secret

            # If no valid secret found, prompt user to configure
            self.logger.error("No valid KeyAuth secret found. Please run keyauth_setup.py to configure.")
            return None

        except Exception as e:
            self.logger.error(f"Failed to load KeyAuth secret: {e}")
            return None
    
    def initialize_protection(self):
        """Initialize advanced protection system"""
        try:
            # Create protection system with KeyAuth integration
            self.protection_system = AdvancedProtection(
                app_name="SCKillTrac[Global]-KeyAuth",
                webhook_url="YOUR_DISCORD_WEBHOOK_URL_HERE"  # Replace with your webhook
            )
            
            # Start protection monitoring
            self.protection_system.start_protection_thread()
            
            self.logger.info("Protection system initialized")
            return True
            
        except Exception as e:
            self.logger.error(f"Protection initialization failed: {e}")
            return False
    
    def authenticate_user(self):
        """Authenticate user with KeyAuth"""
        try:
            # Check if user is blacklisted first
            manager = get_keyauth_manager()
            if manager and manager.api.check_blacklist():
                QMessageBox.critical(None, "Access Denied", 
                                   "Your hardware ID has been blacklisted. Access denied.")
                return False
            
            # Show authentication dialog
            if show_auth_dialog():
                self.keyauth_manager = get_keyauth_manager()
                self.user_data = self.keyauth_manager.get_user_info()
                
                # Log successful authentication
                if self.keyauth_manager:
                    self.keyauth_manager.api.log_activity("User authenticated successfully")
                
                self.logger.info(f"User authenticated: {self.user_data.get('username', 'Unknown')}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Authentication failed: {e}")
            QMessageBox.critical(None, "Authentication Error", 
                               f"Authentication failed: {str(e)}")
            return False
    
    def start_session_monitoring(self):
        """Start session monitoring and validation"""
        try:
            if self.keyauth_manager:
                # Session monitoring is handled by KeyAuthManager
                self.logger.info("Session monitoring started")
                
                # Log application start
                self.keyauth_manager.api.log_activity("SC Kill Tracker started")
                
        except Exception as e:
            self.logger.error(f"Session monitoring failed: {e}")
    
    def run_main_application(self):
        """Run the main SC Kill Tracker application"""
        try:
            # Import and run the existing main application logic
            # This would integrate with your existing SCKillTrac[Global].py
            
            # For now, we'll show a placeholder
            QMessageBox.information(None, "Success", 
                                  f"Welcome to SC Kill Tracker!\n"
                                  f"User: {self.user_data.get('username', 'Unknown')}\n"
                                  f"HWID: {self.user_data.get('hwid', 'Unknown')}\n"
                                  f"Subscription: {self.user_data.get('subscription', 'Unknown')}")
            
            # Here you would call your existing main application logic
            # For example: run_app(root) or similar
            
            return True
            
        except Exception as e:
            self.logger.error(f"Main application failed: {e}")
            return False
    
    def shutdown(self):
        """Graceful shutdown"""
        try:
            if self.keyauth_manager:
                self.keyauth_manager.api.log_activity("SC Kill Tracker shutdown")
            
            if self.protection_system:
                # Protection system cleanup is handled automatically
                pass
            
            self.logger.info("Application shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Shutdown error: {e}")


def main():
    """Main entry point"""
    try:
        # Create and initialize application
        app = KeyAuthSCKillTracker()
        
        if not app.initialize_application():
            sys.exit(1)
        
        # Run main application
        if app.run_main_application():
            # Start Qt event loop
            result = app.app.exec()
        else:
            result = 1
        
        # Cleanup
        app.shutdown()
        sys.exit(result)
        
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
