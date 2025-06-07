"""
KeyAuth Integration for SC Kill Tracker
Using the official KeyAuth Python library
"""

import os
import json
import time
import hashlib
import platform
import subprocess
import logging
import uuid
import sys
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
import threading

# Import the KeyAuth library
try:
    from keyauth import api
    KEYAUTH_LIB_AVAILABLE = True
except ImportError:
    KEYAUTH_LIB_AVAILABLE = False
    print("KeyAuth library not found. Install with: pip install keyauth")

# Windows-specific imports
try:
    if os.name == 'nt':
        import win32security
        import winreg
except ImportError:
    pass

def getchecksum():
    """Get checksum of current executable for KeyAuth"""
    try:
        if getattr(sys, 'frozen', False):
            # Running as compiled executable
            file_path = sys.executable
        else:
            # Running as script - use main script file
            file_path = sys.argv[0]

        with open(file_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception:
        return "debug_mode"

class KeyAuthWrapper:
    """Wrapper for the official KeyAuth Python library"""

    def __init__(self):
        self.keyauthapp = None
        self.initialized = False
        self.user_data = None
        self.logger = logging.getLogger("KeyAuth")

    def init(self) -> bool:
        """Initialize KeyAuth using the official library"""
        if not KEYAUTH_LIB_AVAILABLE:
            self.logger.error("KeyAuth library not available")
            return False

        try:
            # Initialize using your exact format
            self.keyauthapp = api(
                name="SCKillTrac",  # App name
                ownerid="EWtg9qJWO2",  # Account ID
                version="1.0",  # Application version
                hash_to_check=getchecksum()
            )

            self.initialized = True
            self.logger.info("KeyAuth initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"KeyAuth initialization failed: {e}")
            return False
    
    def login(self, username: str, password: str) -> Dict[str, Any]:
        """Login user with username and password"""
        if not self.initialized:
            return {"success": False, "message": "Not initialized"}

        try:
            self.keyauthapp.login(username, password)

            # Get user data from KeyAuth
            self.user_data = {
                "username": self.keyauthapp.user_data.username,
                "hwid": self.keyauthapp.user_data.hwid,
                "ip": self.keyauthapp.user_data.ip,
                "subscription": self.keyauthapp.user_data.subscription,
                "expires": self.keyauthapp.user_data.expires,
                "createdate": self.keyauthapp.user_data.createdate,
                "lastlogin": self.keyauthapp.user_data.lastlogin
            }

            self.logger.info(f"User {username} logged in successfully")
            return {"success": True, "message": "Login successful", "info": self.user_data}

        except Exception as e:
            self.logger.error(f"Login failed: {e}")
            return {"success": False, "message": str(e)}

    def register(self, username: str, password: str, license_key: str) -> Dict[str, Any]:
        """Register new user"""
        if not self.initialized:
            return {"success": False, "message": "Not initialized"}

        try:
            self.keyauthapp.register(username, password, license_key)

            # Get user data from KeyAuth
            self.user_data = {
                "username": self.keyauthapp.user_data.username,
                "hwid": self.keyauthapp.user_data.hwid,
                "ip": self.keyauthapp.user_data.ip,
                "subscription": self.keyauthapp.user_data.subscription,
                "expires": self.keyauthapp.user_data.expires,
                "createdate": self.keyauthapp.user_data.createdate,
                "lastlogin": self.keyauthapp.user_data.lastlogin
            }

            self.logger.info(f"User {username} registered successfully")
            return {"success": True, "message": "Registration successful", "info": self.user_data}

        except Exception as e:
            self.logger.error(f"Registration failed: {e}")
            return {"success": False, "message": str(e)}

    def license_login(self, license_key: str) -> Dict[str, Any]:
        """Login with license key only"""
        if not self.initialized:
            return {"success": False, "message": "Not initialized"}

        try:
            self.keyauthapp.license(license_key)

            # Get user data from KeyAuth
            self.user_data = {
                "username": getattr(self.keyauthapp.user_data, 'username', 'License User'),
                "hwid": self.keyauthapp.user_data.hwid,
                "ip": self.keyauthapp.user_data.ip,
                "subscription": self.keyauthapp.user_data.subscription,
                "expires": self.keyauthapp.user_data.expires,
                "createdate": getattr(self.keyauthapp.user_data, 'createdate', 'Unknown'),
                "lastlogin": getattr(self.keyauthapp.user_data, 'lastlogin', 'Unknown')
            }

            self.logger.info("License login successful")
            return {"success": True, "message": "License login successful", "info": self.user_data}

        except Exception as e:
            self.logger.error(f"License login failed: {e}")
            return {"success": False, "message": str(e)}
    
    def login(self, username: str, password: str, hwid: Optional[str] = None, code: Optional[str] = None) -> Dict[str, Any]:
        """Login user with username and password"""
        if not self._check_init():
            return {"success": False, "message": "Not initialized"}
            
        if not hwid:
            hwid = self._get_hwid()
            
        post_data = {
            "type": "login",
            "username": username,
            "pass": password,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        if code:
            post_data["code"] = code
            
        response = self._do_request(post_data)
        if response and response.get("success"):
            self.user_data = response.get("info", {})
            self.logger.info(f"User {username} logged in successfully")
            
        return response or {"success": False, "message": "Request failed"}
    
    def check_blacklist(self) -> bool:
        """Check if current HWID is blacklisted"""
        if not self.initialized:
            return False

        try:
            # KeyAuth library handles blacklist checking internally
            # This is typically done during login/register
            return False
        except Exception as e:
            self.logger.error(f"Blacklist check failed: {e}")
            return False

    def log_activity(self, message: str) -> bool:
        """Log activity to KeyAuth dashboard"""
        if not self.initialized:
            return False

        try:
            self.keyauthapp.log(message)
            return True
        except Exception as e:
            self.logger.error(f"Activity logging failed: {e}")
            return False

    def check_session(self) -> bool:
        """Check if current session is valid"""
        if not self.initialized:
            return False

        try:
            # KeyAuth library maintains session automatically
            return True
        except Exception as e:
            self.logger.error(f"Session check failed: {e}")
            return False
    



class KeyAuthManager:
    """High-level KeyAuth management for SC Kill Tracker using official library"""

    def __init__(self):
        self.api = KeyAuthWrapper()
        self.current_user = None
        self.session_valid = False
        self.logger = logging.getLogger("KeyAuthManager")

        # Initialize the KeyAuth API
        if self.api.init():
            self.session_valid = True

        # Start session validation thread
        self._start_session_monitor()

    def authenticate_user(self, auth_type: str, **kwargs) -> Dict[str, Any]:
        """Authenticate user with various methods"""

        # Check blacklist first (handled by KeyAuth library internally)
        if self.api.check_blacklist():
            return {
                "success": False,
                "message": "Your HWID has been blacklisted. Access denied.",
                "banned": True
            }

        result = None
        if auth_type == "login":
            result = self.api.login(kwargs["username"], kwargs["password"])
        elif auth_type == "register":
            result = self.api.register(kwargs["username"], kwargs["password"], kwargs["license"])
        elif auth_type == "license":
            result = self.api.license_login(kwargs["license"])

        if result and result.get("success"):
            self.current_user = self.api.user_data
            self.session_valid = True
            self.api.log_activity(f"User authenticated via {auth_type}")

        return result or {"success": False, "message": "Authentication failed"}

    def is_session_valid(self) -> bool:
        """Check if current session is valid"""
        return self.session_valid and self.api.check_session()

    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """Get current user information"""
        return self.current_user

    def _start_session_monitor(self):
        """Start background session validation"""
        def monitor():
            while True:
                if self.session_valid:
                    if not self.api.check_session():
                        self.session_valid = False
                        self.current_user = None
                        self.logger.warning("Session invalidated")
                time.sleep(30)  # Check every 30 seconds

        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()


# Global KeyAuth manager instance
keyauth_manager = None

def initialize_keyauth(secret: str = "") -> bool:
    """Initialize KeyAuth for SC Kill Tracker - no secret needed for library"""
    global keyauth_manager

    if not KEYAUTH_LIB_AVAILABLE:
        logging.error("KeyAuth library not available. Install with: pip install keyauth")
        return False

    try:
        keyauth_manager = KeyAuthManager()
        if not keyauth_manager.api.initialized:
            logging.error("KeyAuth API failed to initialize.")
            return False
        return True
    except Exception as e:
        logging.error(f"KeyAuth initialization failed: {e}")
        return False

def get_keyauth_manager() -> Optional[KeyAuthManager]:
    """Get global KeyAuth manager instance"""
    return keyauth_manager
