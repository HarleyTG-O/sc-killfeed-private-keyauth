"""
KeyAuth Integration for SC Kill Tracker
Full authentication and user management system with HWID banning capabilities
"""

import os
import json
import time
import hashlib
import platform
import subprocess
import requests
import logging
import uuid
import sys
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
import threading

# Windows-specific imports
try:
    if os.name == 'nt':
        import win32security
        import winreg
except ImportError:
    pass

class KeyAuthAPI:
    """Enhanced KeyAuth API client with full feature support"""
    
    def __init__(self, name: str, ownerid: str, secret: str, version: str, api_url: str = "https://keyauth.win/api/1.3/"):
        self.name = name
        self.ownerid = ownerid
        self.secret = secret
        self.version = version
        self.api_url = api_url
        self.sessionid = ""
        self.initialized = False
        self.user_data = None
        self.app_data = None
        
        # Initialize logging
        self.logger = logging.getLogger(f"KeyAuth.{name}")
        
        # Auto-initialize
        self.init()
    
    def init(self) -> bool:
        """Initialize KeyAuth application"""
        if self.sessionid:
            self.logger.warning("Already initialized!")
            return True
            
        try:
            post_data = {
                "type": "init",
                "ver": self.version,
                "hash": self._get_file_hash(),
                "name": self.name,
                "ownerid": self.ownerid,
                "secret": self.secret
            }
            
            response = self._do_request(post_data)
            if not response:
                return False
                
            if response.get("success"):
                self.sessionid = response["sessionid"]
                self.initialized = True
                self.logger.info("KeyAuth initialized successfully")
                return True
            else:
                self.logger.error(f"Init failed: {response.get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            self.logger.error(f"Init exception: {e}")
            return False
    
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
    
    def register(self, username: str, password: str, license_key: str, hwid: Optional[str] = None) -> Dict[str, Any]:
        """Register new user"""
        if not self._check_init():
            return {"success": False, "message": "Not initialized"}
            
        if not hwid:
            hwid = self._get_hwid()
            
        post_data = {
            "type": "register",
            "username": username,
            "pass": password,
            "key": license_key,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        response = self._do_request(post_data)
        if response and response.get("success"):
            self.user_data = response.get("info", {})
            self.logger.info(f"User {username} registered successfully")
            
        return response or {"success": False, "message": "Request failed"}
    
    def license_login(self, license_key: str, hwid: Optional[str] = None, code: Optional[str] = None) -> Dict[str, Any]:
        """Login with license key only"""
        if not self._check_init():
            return {"success": False, "message": "Not initialized"}
            
        if not hwid:
            hwid = self._get_hwid()
            
        post_data = {
            "type": "license",
            "key": license_key,
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
            self.logger.info("License login successful")
            
        return response or {"success": False, "message": "Request failed"}
    
    def ban_user(self) -> Dict[str, Any]:
        """Ban current user and blacklist their HWID"""
        if not self._check_init():
            return {"success": False, "message": "Not initialized"}
            
        post_data = {
            "type": "ban",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        response = self._do_request(post_data)
        if response and response.get("success"):
            self.logger.warning("User banned and HWID blacklisted")
            
        return response or {"success": False, "message": "Request failed"}
    
    def check_blacklist(self, hwid: Optional[str] = None) -> bool:
        """Check if HWID is blacklisted"""
        if not self._check_init():
            return False
            
        if not hwid:
            hwid = self._get_hwid()
            
        post_data = {
            "type": "checkblacklist",
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        response = self._do_request(post_data)
        return response and not response.get("success")  # Returns True if blacklisted
    
    def check_session(self) -> bool:
        """Check if current session is valid"""
        if not self._check_init():
            return False
            
        post_data = {
            "type": "check",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        response = self._do_request(post_data)
        return response and response.get("success", False)
    
    def log_activity(self, message: str) -> bool:
        """Log activity to KeyAuth dashboard"""
        if not self._check_init():
            return False
            
        post_data = {
            "type": "log",
            "pcuser": os.getenv('USERNAME', 'Unknown'),
            "message": message,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        response = self._do_request(post_data)
        return response and response.get("success", False)
    
    def get_variable(self, var_name: str) -> Optional[str]:
        """Get application variable"""
        if not self._check_init():
            return None
            
        post_data = {
            "type": "var",
            "varid": var_name,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        response = self._do_request(post_data)
        if response and response.get("success"):
            return response.get("message")
        return None
    
    def get_user_variable(self, var_name: str) -> Optional[str]:
        """Get user-specific variable"""
        if not self._check_init():
            return None
            
        post_data = {
            "type": "getvar",
            "var": var_name,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        response = self._do_request(post_data)
        if response and response.get("success"):
            return response.get("response")
        return None
    
    def set_user_variable(self, var_name: str, var_data: str) -> bool:
        """Set user-specific variable"""
        if not self._check_init():
            return False
            
        post_data = {
            "type": "setvar",
            "var": var_name,
            "data": var_data,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        response = self._do_request(post_data)
        return response and response.get("success", False)
    
    def fetch_online_users(self) -> List[Dict[str, Any]]:
        """Get list of online users"""
        if not self._check_init():
            return []
            
        post_data = {
            "type": "fetchOnline",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        response = self._do_request(post_data)
        if response and response.get("success"):
            return response.get("users", [])
        return []
    
    def fetch_app_stats(self) -> Dict[str, Any]:
        """Fetch application statistics"""
        if not self._check_init():
            return {}
            
        post_data = {
            "type": "fetchStats",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        
        response = self._do_request(post_data)
        if response and response.get("success"):
            self.app_data = response.get("appinfo", {})
            return self.app_data
        return {}
    
    def _get_hwid(self) -> str:
        """Get hardware ID for current system"""
        try:
            if platform.system() == "Windows":
                # Use SID method for Windows
                winuser = os.getlogin()
                sid = win32security.LookupAccountName(None, winuser)[0]
                hwid = win32security.ConvertSidToStringSid(sid)
                return hwid
            elif platform.system() == "Linux":
                with open("/etc/machine-id") as f:
                    return f.read().strip()
            elif platform.system() == "Darwin":
                output = subprocess.Popen(
                    "ioreg -l | grep IOPlatformSerialNumber",
                    stdout=subprocess.PIPE,
                    shell=True
                ).communicate()[0]
                serial = output.decode().split('=', 1)[1].replace(' ', '')
                return serial[1:-2]
        except Exception as e:
            self.logger.error(f"HWID generation failed: {e}")
            
        # Fallback HWID
        return hashlib.md5(f"{platform.node()}{platform.system()}".encode()).hexdigest()
    
    def _get_file_hash(self) -> str:
        """Get hash of current executable"""
        try:
            if getattr(sys, 'frozen', False):
                # Running as compiled executable
                file_path = sys.executable
            else:
                # Running as script
                file_path = sys.argv[0]
                
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return "debug_mode"
    
    def _check_init(self) -> bool:
        """Check if API is initialized"""
        if not self.initialized:
            self.logger.error("KeyAuth not initialized")
            return False
        return True
    
    def _do_request(self, post_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make HTTP request to KeyAuth API"""
        try:
            response = requests.post(self.api_url, data=post_data, timeout=10)
            response.raise_for_status()
            
            if response.text == "KeyAuth_Invalid":
                self.logger.error("Invalid KeyAuth application")
                return None
                
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            return None
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON decode failed: {e}")
            return None


class KeyAuthManager:
    """High-level KeyAuth management for SC Kill Tracker"""
    
    def __init__(self, config: Dict[str, str]):
        self.api = KeyAuthAPI(
            name=config["name"],
            ownerid=config["ownerid"], 
            secret=config["secret"],
            version=config["version"]
        )
        self.current_user = None
        self.session_valid = False
        self.logger = logging.getLogger("KeyAuthManager")
        
        # Start session validation thread
        self._start_session_monitor()
    
    def authenticate_user(self, auth_type: str, **kwargs) -> Dict[str, Any]:
        """Authenticate user with various methods"""
        
        # Check blacklist first
        if self.api.check_blacklist():
            return {
                "success": False,
                "message": "Your HWID has been blacklisted. Access denied.",
                "banned": True
            }
        
        result = None
        if auth_type == "login":
            result = self.api.login(kwargs["username"], kwargs["password"], kwargs.get("code"))
        elif auth_type == "register":
            result = self.api.register(kwargs["username"], kwargs["password"], kwargs["license"])
        elif auth_type == "license":
            result = self.api.license_login(kwargs["license"], kwargs.get("code"))
        
        if result and result.get("success"):
            self.current_user = self.api.user_data
            self.session_valid = True
            self.api.log_activity(f"User authenticated via {auth_type}")
            
        return result or {"success": False, "message": "Authentication failed"}
    
    def ban_current_user(self, reason: str = "Violation detected") -> bool:
        """Ban current user and log reason"""
        if not self.session_valid:
            return False
            
        self.api.log_activity(f"User banned: {reason}")
        result = self.api.ban_user()
        
        if result.get("success"):
            self.session_valid = False
            self.current_user = None
            return True
        return False
    
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


# Configuration for SC Kill Tracker
KEYAUTH_CONFIG = {
    "name": "SCKillTrac",
    "ownerid": "EWtg9qJWO2", 
    "secret": "",  # Add your secret here
    "version": "1.0"
}

# Global KeyAuth manager instance
keyauth_manager = None

def initialize_keyauth(secret: str) -> bool:
    """Initialize KeyAuth for SC Kill Tracker"""
    global keyauth_manager
    
    config = KEYAUTH_CONFIG.copy()
    config["secret"] = secret
    
    try:
        keyauth_manager = KeyAuthManager(config)
        return True
    except Exception as e:
        logging.error(f"KeyAuth initialization failed: {e}")
        return False

def get_keyauth_manager() -> Optional[KeyAuthManager]:
    """Get global KeyAuth manager instance"""
    return keyauth_manager
