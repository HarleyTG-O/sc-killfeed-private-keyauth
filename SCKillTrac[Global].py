# -*- coding: utf-8 -*-

# ===================================================================
# SC KILL TRACKER - PERFORMANCE OPTIMIZED & ORGANIZED WITH KEYAUTH
# ===================================================================
# KeyAuth Integration Features:
# - Secure authentication with username/password and license keys
# - HWID tracking and hardware-based banning
# - Real-time session validation and monitoring
# - Admin panel for user management and blacklist control
# - Advanced protection system with automatic user banning
# - Discord webhook notifications for all events
#
# The following optimizations have been applied to improve performance:

# === Python Standard Library - Core ===
import base64
import ctypes
import datetime
import glob
import json
import logging
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from tkinter import colorchooser
import traceback
import urllib
import uuid
import webbrowser
import winreg
import zipfile
from collections import deque
from datetime import datetime
from functools import lru_cache, wraps
from io import BytesIO, StringIO
from pathlib import Path
from threading import Lock
from typing import Optional, Tuple
from turtle import fd

# === Python Standard Library - GUI ===
import tkinter as tk
import tkinter.messagebox as messagebox_tk
from tkinter import filedialog, font, messagebox, scrolledtext, ttk

# === Windows-Specific Imports ===
import win32api
from Crypto.Random import get_random_bytes
import winreg

# === Third-Party Library - Cryptography ===
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# === Third-Party Library - Core ===
import psutil
import requests

# === Third-Party Library - GUI ===
from PIL import Image, ImageTk
import pystray
from pypresence import Presence

# === Qt Framework - Core ===
from PySide6.QtCore import (
    QMetaObject, QObject, QPoint, QPointF, QPropertyAnimation, QRect, QRectF,
    QSettings, QSize, QTimer, QUrl, Qt, Signal, Slot, QByteArray
)

# === Qt Framework - GUI ===
from PySide6.QtGui import (
    QColor, QDesktopServices, QFont, QGuiApplication, QIcon,
    QImage, QKeySequence, QLinearGradient, QMovie, QPainter, QPainterPath, QPen, QPixmap, QShortcut
)

# === Qt Framework - Widgets ===
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QFrame, QGraphicsDropShadowEffect,
    QGraphicsOpacityEffect, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QMainWindow, QMenu, QMessageBox, QPushButton, QScrollArea,
    QSizePolicy, QSizeGrip, QSpacerItem, QSplashScreen, QSystemTrayIcon, QTabWidget,
    QTextEdit, QVBoxLayout, QWidget
)

# === Internal Application Imports ===
from actors import ACTORS
from crash import get_system_info, handle_crash
from protection import AdvancedProtection
from starcitizenapi import __main__
# from scktstartup_args import get_startup_flag, startup_flag

# === KeyAuth Integration ===
try:
    from keyauth_integration import initialize_keyauth, get_keyauth_manager
    from keyauth_dialogs import show_auth_dialog
    KEYAUTH_AVAILABLE = True
    print("KeyAuth integration loaded successfully")
except ImportError as e:
    KEYAUTH_AVAILABLE = False
    print(f"KeyAuth integration not available: {e}")
    print("Falling back to local authentication system")

# Global variables for console capture
app_console_widget = None
console_buffer = []  # Changed to list for better memory management
console_memory_limit = 2000  # Keep last 2000 lines in memory
original_stdout = sys.stdout
original_stderr = sys.stderr

class ConsoleRedirector:
    """Redirects console output to both original console and app console widget"""
    def __init__(self, original_stream, is_stderr=False):
        self.original_stream = original_stream
        self.is_stderr = is_stderr
        self.buffer = []

    def write(self, text):
        global console_buffer, console_memory_limit

        # Write to original console
        self.original_stream.write(text)
        self.original_stream.flush()

        # Store in local buffer for startup
        self.buffer.append(text)

        # Store in global memory buffer with timestamp
        if text.strip():  # Only store non-empty lines
            from datetime import datetime
            timestamp = datetime.now().strftime("%H:%M:%S")
            console_buffer.append(f"[{timestamp}] {text.rstrip()}")

            # Limit memory buffer size
            if len(console_buffer) > console_memory_limit:
                console_buffer = console_buffer[-console_memory_limit:]

        # If app console widget is available, write to it
        if app_console_widget and text.strip():
            try:
                # Use thread-safe method to update GUI
                app_console_widget.after_idle(self._update_console, text)
            except:
                pass  # Ignore errors if widget is not ready

    def _update_console(self, text):
        """Thread-safe method to update console widget"""
        try:
            app_console_widget.config(state=tk.NORMAL)
            app_console_widget.insert(tk.END, text)
            app_console_widget.see(tk.END)
            app_console_widget.config(state=tk.DISABLED)

            # Limit console widget buffer size (keep last 1500 lines)
            lines = app_console_widget.get("1.0", tk.END).split('\n')
            if len(lines) > 1500:
                app_console_widget.config(state=tk.NORMAL)
                app_console_widget.delete("1.0", f"{len(lines)-1500}.0")
                app_console_widget.config(state=tk.DISABLED)
        except:
            pass  # Ignore errors if widget is destroyed

    def flush(self):
        self.original_stream.flush()

def restore_console_output():
    """Restore original console output streams"""
    global original_stdout, original_stderr
    sys.stdout = original_stdout
    sys.stderr = original_stderr

def ensure_window_on_top(window):
    """Ensure a window stays on top with proper focus"""
    try:
        if hasattr(window, 'lift'):  # Tkinter window
            window.lift()
            window.focus_force()
            window.attributes('-topmost', True)
            # Temporarily disable topmost to allow normal interaction
            window.after(100, lambda: window.attributes('-topmost', False))
        elif hasattr(window, 'raise_'):  # Qt window
            window.raise_()
            window.activateWindow()
            window.show()
    except Exception as e:
        logging.warning(f"Failed to bring window to top: {e}")

def create_modal_dialog_qt(parent=None, title="Dialog", width=400, height=300):
    """Create a properly configured Qt modal dialog that stays on top"""
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.setWindowModality(Qt.ApplicationModal)

    # Use scaled size
    scaled_width, scaled_height = get_qt_scaled_size(width, height)
    dialog.setFixedSize(scaled_width, scaled_height)

    # Configure window flags for staying on top
    dialog.setWindowFlags(
        Qt.Dialog |
        Qt.WindowStaysOnTopHint |
        Qt.WindowSystemMenuHint |
        Qt.WindowTitleHint |
        Qt.WindowCloseButtonHint
    )

    # Ensure it appears on top
    dialog.raise_()
    dialog.activateWindow()

    return dialog

# Create redirectors
stdout_redirector = ConsoleRedirector(original_stdout)
stderr_redirector = ConsoleRedirector(original_stderr, is_stderr=True)

# Redirect stdout and stderr
sys.stdout = stdout_redirector
sys.stderr = stderr_redirector

# === Dialog and MessageBox Management ===
import tkinter.messagebox as messagebox_tk

# Global reference to main window for proper dialog parenting
main_window_ref = None

def set_main_window_ref(window):
    """Set the main window reference for proper dialog parenting"""
    global main_window_ref
    main_window_ref = window

def show_message(title, message, msg_type="info", parent=None):
    """Show message dialog that stays on top of SC Kill Tracker windows"""
    # Use provided parent or main window reference
    parent_window = parent or main_window_ref

    try:
        if parent_window:
            # Ensure parent window is on top first
            parent_window.lift()
            parent_window.attributes('-topmost', True)
            parent_window.after(10, lambda: parent_window.attributes('-topmost', False))

        # Show message with proper parent
        if msg_type == "info":
            result = messagebox_tk.showinfo(title, message, parent=parent_window)
        elif msg_type == "warning":
            result = messagebox_tk.showwarning(title, message, parent=parent_window)
        elif msg_type == "error":
            result = messagebox_tk.showerror(title, message, parent=parent_window)
        elif msg_type == "question":
            result = messagebox_tk.askyesno(title, message, parent=parent_window)
        else:
            result = messagebox_tk.showinfo(title, message, parent=parent_window)

        return result
    except Exception as e:
        # Fallback to standard messagebox if parent fails
        print(f"Dialog parent error: {e}")
        if msg_type == "info":
            return messagebox_tk.showinfo(title, message)
        elif msg_type == "warning":
            return messagebox_tk.showwarning(title, message)
        elif msg_type == "error":
            return messagebox_tk.showerror(title, message)
        elif msg_type == "question":
            return messagebox_tk.askyesno(title, message)
        else:
            return messagebox_tk.showinfo(title, message)

# === Logging Setup ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# === Constants ===
VERSION = "v0.1.3.6.4"
BUILD_TYPE = "Beta"  
DEPLOYMENT_SCOPE = "Global"
splash_done = threading.Event()   
SPLASH_TIMEOUT = 20000
api_key = "ydQHZKCi5wTcknzBkEpBjfRa1JbFZSbq"
KEY = b"OjPs60LNS7LbbroAuPXDkwLRipgfH6hIFA6wvuBxkg4="
client = __main__.Client(api_key)  # Use lowercase to avoid confusion

LOCAL_APPDATA = os.getenv('LOCALAPPDATA')
CONFIG_PATH = os.path.join(LOCAL_APPDATA, "Harley's Studio", "Star Citizen Kill Tracker", "config.json")

DEFAULT_LOCATIONS = [
    r"C:\Program Files\Roberts Space Industries\StarCitizen\LIVE\Game.log",
    r"D:\Roberts Space Industries\StarCitizen\LIVE\Game.log",
]
DEFAULT_PTU_LOCATIONS = [
    r"C:\Program Files\Roberts Space Industries\StarCitizen\PTU\Game.log",
    r"D:\Roberts Space Industries\StarCitizen\PTU\Game.log",
]
DEFAULT_EPTU_LOCATIONS = [
    r"C:\Program Files\Roberts Space Industries\StarCitizen\EPTU\Game.log",
    r"D:\Roberts Space Industries\StarCitizen\EPTU\Game.log",
]

GITHUB_API_URL = "https://api.github.com/repos/HarleyTG-O/sc-killfeed/contents/client.json"

DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1367286978416087040/KQCj7DcBqxYj6uIbH8ShxR9bmtdIPgL5I3QsAYTqQ2XVZ_RENB0xF-Aq_eLRzthvUooV"
PVE_WEBHOOK_URL = "https://discord.com/api/webhooks/1368067202011627621/tEeWz-lhjEuO9UlxIccdrU-mlxKemNROt5PIIj5TZwRsTzKYrK-1Q3GZAGzzPvesY873"
DEATH_REGEX_WEBHOOK_URL = "https://discord.com/api/webhooks/1368076403106517064/Qd29yy25CqqHEjvVlPHFTZ1xxajMoIlS7hpWSHdMvVLM6iBQ7WuFevPS3IyldtfTABi1"

UserLoginWebhook_URL = "https://discord.com/api/webhooks/1379904107719954465/ysG7W1JHrcEqmH2V8UpCQKjWKOtPp3p8bkcYPjqORh9ITKe8YG0dI0dQ6JtZxMyQRMg5"
UserGlobalWebhook_URL = "https://discord.com/api/webhooks/1380203199713251539/nlIhFB4CjVluoODvJYCLzNpgYuCryirglD4dV37PAYmBff8246rbV4MsQOCLFKd0Koen"


LOGO_URL = "https://raw.githubusercontent.com/HarleyTG-O/sc-killfeed/main/logo.png"
PROCESS_STRING = 'SCKillTrac'

FONT_URL = "https://www.ffonts.net/Segoe-Boot-Semilight.font.zip"
FONT_NAME = "Segoe Boot Semilight"
FONT_FOLDER = os.path.join(os.environ["WINDIR"], "Fonts")
FONT_TTF = "segoeui.ttf"
FONT_ZIP_PATH = "segoe_boot_semilight.zip"
FONT_PATH = os.path.join(FONT_FOLDER, FONT_TTF)

# Ensure the settings directory exists
SETTINGS_DIR = os.path.join(os.getenv('LOCALAPPDATA'), "Harley's Studio", "Star Citizen Kill Tracker")
os.makedirs(SETTINGS_DIR, exist_ok=True)
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "Settings.json")
USER_LANGUAGE_FILE = os.path.join(SETTINGS_DIR, "userlanguage.json")
offline_mode_flag = None

DEATH_REGEX = re.compile(
    r"<(?P<timestamp>[\d\-T:.Z]+)> \[Notice\] <Actor Death> CActor::Kill: '"
    r"(?P<victim>.*?)' \[(?P<victim_id>\d+)\] "
    r"in zone '(?P<zone>.*?)' killed by '(?P<killer>.*?)' \[(?P<killer_id>\d+)\] "
    r"using '(?P<weapon>.*?)' (?:\[Class (?P<class>.*?)\])? "
    r"with damage type '(?P<damage_type>.*?)'(?:, .*?)?"
)


# === Runtime Globals ===
running = True
kill_tracking = True
lock = threading.Lock()
app_logo = None

# === Version & Update Logic ===
# Dynamic version text generator
def get_version_text():
    base = f"{VERSION}-{BUILD_TYPE}"
    if DEPLOYMENT_SCOPE == "Global":
        return f"{base} (Global)"
    elif DEPLOYMENT_SCOPE == "User":
        return f"{base} (Personal)"
    else:  # Org
        return f"{base} (Organization)"

def load_user_language():
    try:
        with open(USER_LANGUAGE_FILE, "r") as f:
            data = json.load(f)
            return data.get("language", "EN-US")
    except Exception:
        return "EN-US"

def initialize_keyauth_system():
    """Initialize KeyAuth system with application secret"""
    if not KEYAUTH_AVAILABLE:
        return False

    try:
        # TODO: Replace with your actual KeyAuth secret
        # You can get this from your KeyAuth dashboard
        keyauth_secret = "YOUR_KEYAUTH_SECRET_HERE"

        # For production, load from secure storage or environment variable
        # keyauth_secret = os.getenv("KEYAUTH_SECRET") or load_from_secure_storage()

        if keyauth_secret == "YOUR_KEYAUTH_SECRET_HERE":
            logging.warning("KeyAuth secret not configured. Please set your actual secret.")
            return False

        success = initialize_keyauth(keyauth_secret)
        if success:
            logging.info("KeyAuth system initialized successfully")
            return True
        else:
            logging.error("Failed to initialize KeyAuth system")
            return False

    except Exception as e:
        logging.error(f"KeyAuth initialization error: {e}")
        return False

def authenticate_with_keyauth():
    """Authenticate user with KeyAuth system"""
    if not KEYAUTH_AVAILABLE:
        return False, None

    try:
        # Check if user is blacklisted first
        manager = get_keyauth_manager()
        if manager and manager.api.check_blacklist():
            QMessageBox.critical(None, "Access Denied",
                               "Your hardware ID has been blacklisted. Access denied.")
            return False, None

        # Show KeyAuth authentication dialog
        if show_auth_dialog():
            manager = get_keyauth_manager()
            if manager:
                user_info = manager.get_user_info()

                # Convert KeyAuth user data to SC Kill Tracker format
                user_data = {
                    "Username": user_info.get("username", "Unknown"),
                    "SCKillTrac ID": f"{user_info.get('username', 'Unknown')}@SCKillTrac-KeyAuth",
                    "UUID": user_info.get("hwid", str(uuid.uuid4())),
                    "HWID": user_info.get("hwid", "Unknown"),
                    "IP": user_info.get("ip", "Unknown"),
                    "Subscription": user_info.get("subscription", "Unknown"),
                    "KeyAuth_User": True,  # Flag to identify KeyAuth users
                    "Expires": user_info.get("expires", "Unknown"),
                    "Created": user_info.get("createdate", "Unknown")
                }

                # Log successful authentication
                manager.api.log_activity("SC Kill Tracker authentication successful")

                logging.info(f"KeyAuth authentication successful for user: {user_data['Username']}")
                return True, user_data

        return False, None

    except Exception as e:
        logging.error(f"KeyAuth authentication error: {e}")
        QMessageBox.critical(None, "Authentication Error",
                           f"KeyAuth authentication failed: {str(e)}")
        return False, None

def start_keyauth_session_monitoring():
    """Start background session monitoring for KeyAuth users"""
    if not KEYAUTH_AVAILABLE:
        return

    def monitor_session():
        """Background thread to monitor KeyAuth session validity"""
        while True:
            try:
                manager = get_keyauth_manager()
                if manager and not manager.is_session_valid():
                    logging.warning("KeyAuth session expired or invalid")

                    # Show session expired message
                    QMessageBox.critical(None, "Session Expired",
                                       "Your KeyAuth session has expired. Please restart the application.")

                    # Log session expiry
                    try:
                        manager.api.log_activity("Session expired - application terminating")
                    except:
                        pass

                    # Terminate application
                    os._exit(1)

                # Check every 30 seconds
                time.sleep(30)

            except Exception as e:
                logging.error(f"Session monitoring error: {e}")
                time.sleep(60)  # Wait longer on error

    # Start monitoring thread
    monitor_thread = threading.Thread(target=monitor_session, daemon=True)
    monitor_thread.start()
    logging.info("KeyAuth session monitoring started")

def fetch_remote_flags():
    flags = {
        "disable_client": False,
        "mandatory_update": False,
        "required_version": VERSION
    }

    try:
        response = requests.get(GITHUB_API_URL)
        if response.ok:
            content = response.json()
            decoded = base64.b64decode(content["content"]).decode('utf-8')
            config = json.loads(decoded)

            flags["disable_client"] = config.get("disable_client", False)
            remote_version = config.get("version", VERSION)
            flags["required_version"] = remote_version

            if compare_versions(remote_version, VERSION):
                flags["mandatory_update"] = True
        else:
            logging.error(f"Failed to fetch config.json: {response.status_code}")
    except Exception:
        logging.exception("Exception during update check")

    return flags

def compare_versions(remote_version, current_version):
    """Compare two semantic version strings and return True if remote is newer."""
    remote_parts = list(map(int, remote_version.lstrip("v").split('.')))
    current_parts = list(map(int, current_version.lstrip("v").split('.')))
    return remote_parts > current_parts

def show_mandatory_update_popup(remote_version):
    app = QApplication.instance() or QApplication(sys.argv)

    msg_box = QMessageBox()
    msg_box.setIcon(QMessageBox.Critical)
    msg_box.setWindowTitle("Mandatory Update Required")
    msg_box.setText(
        f"This version ({VERSION}) is outdated.\n\n"
        f"Please update to version {remote_version} to continue using the client.\n\n"
        "Visit the GitHub Releases page to download the latest version."
    )

    # Load your logo pixmap and set it as window icon
    pixmap = load_global_logo()
    if pixmap and not pixmap.isNull():
        scaled = pixmap.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        msg_box.setWindowIcon(QIcon(scaled))
    else:
        logging.warning("Global logo failed to load for mandatory update popup.")

    msg_box.exec()


from pathlib import Path

STARTUP_ARGS_PATH = Path("C:/Program Files/Harley's Studio/Star Citizen Kill Tracker/startup_args.txt")


def get_startup_flag():
    """Read all startup flags from the file, stripping any '--' prefix."""
    if STARTUP_ARGS_PATH.exists():
        with open(STARTUP_ARGS_PATH, "r") as f:
            flags = set()
            for line in f:
                flag = line.strip().lower()
                if flag.startswith("--"):
                    flag = flag[2:]
                if flag:
                    flags.add(flag)
        return flags
    return set()

startup_flag = get_startup_flag()

# --- Startup Flags ---
if "fastload" in startup_flag:
    SPLASH_TIMEOUT = 1000
    print("Fastload mode enabled: Splash timeout reduced.")

if "dev" in startup_flag:
    logging.getLogger().setLevel(logging.DEBUG)
    print("Developer mode enabled: Debug logging on.")
else:
    # Set logging to WARNING level for normal users to reduce console spam
    logging.getLogger().setLevel(logging.WARNING)

if "disableoverlay" in startup_flag:
    OVERLAY_ENABLED = False
    print("Overlay is disabled by startup flag.")
else:
    OVERLAY_ENABLED = True

if "disablediscordrpc" in startup_flag:
    ENABLE_DISCORD_RPC = False
    print("Discord RPC is disabled by startup flag.")
else:
    ENABLE_DISCORD_RPC = True

if "disablewebhook" in startup_flag:
    ENABLE_DISCORD_WEBHOOKS = False
    print("Discord webhooks/relays are disabled by startup flag.")
else:
    ENABLE_DISCORD_WEBHOOKS = True


import ctypes

def get_scale_factor():
    """Calculate scaling factor based on screen resolution with proper high-DPI support"""
    try:
        import ctypes
        from ctypes import wintypes

        # Set DPI awareness for better scaling detection
        try:
            # Try to set per-monitor DPI awareness (Windows 10+)
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except:
            try:
                # Fallback to system DPI awareness
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except:
                pass

        # Get actual screen dimensions
        try:
            user32 = ctypes.windll.user32
            screen_width = user32.GetSystemMetrics(0)
            screen_height = user32.GetSystemMetrics(1)

            # Get DPI scaling factor
            try:
                dc = user32.GetDC(0)
                dpi_x = ctypes.windll.gdi32.GetDeviceCaps(dc, 88)  # LOGPIXELSX
                dpi_y = ctypes.windll.gdi32.GetDeviceCaps(dc, 90)  # LOGPIXELSY
                user32.ReleaseDC(0, dc)

                # Standard DPI is 96
                dpi_scale_x = dpi_x / 96.0
                dpi_scale_y = dpi_y / 96.0
                dpi_scale = min(dpi_scale_x, dpi_scale_y)
            except:
                dpi_scale = 1.0

        except:
            # Fallback for other OS or if Windows API fails
            try:
                import tkinter as tk
                temp_root = tk.Tk()
                temp_root.withdraw()
                screen_width = temp_root.winfo_screenwidth()
                screen_height = temp_root.winfo_screenheight()
                temp_root.destroy()
                dpi_scale = 1.0
            except:
                screen_width = 1920
                screen_height = 1080
                dpi_scale = 1.0

        # Base scaling on 1920x1080 (100% scaling)
        base_width, base_height = 1920, 1080

        # Calculate resolution-based scaling
        scale_x = screen_width / base_width
        scale_y = screen_height / base_height
        resolution_scale = min(scale_x, scale_y)

        # Combine DPI and resolution scaling
        combined_scale = resolution_scale * dpi_scale

        # Set reasonable bounds for scaling
        # Allow scaling up to 3.0 for 4K+ displays, minimum 0.7 for very small displays
        final_scale = max(0.7, min(3.0, combined_scale))

        # Special handling for common high-resolution displays
        if screen_width >= 3840:  # 4K and above
            final_scale = max(final_scale, 1.8)
        elif screen_width >= 2560:  # 1440p and ultrawide
            final_scale = max(final_scale, 1.3)
        elif screen_width == 1920 and screen_height == 1080:  # Exact 1080p - use original scale
            final_scale = 1.0
        elif screen_width >= 1920:  # 1080p+ but not exact 1080p
            final_scale = max(final_scale, 1.0)

        return final_scale

    except Exception as e:
        logging.warning(f"Failed to calculate scale factor: {e}")
        return 1.0  # Fallback to no scaling

def get_qt_scaled_size(base_width, base_height):
    """Get scaled size for Qt widgets based on current scale factor"""
    scale = get_scale_factor()
    return int(base_width * scale), int(base_height * scale)

def get_qt_scaled_font_size(base_size):
    """Get scaled font size for Qt widgets"""
    scale = get_scale_factor()
    scaled_size = int(base_size * scale)

    # Better minimum font sizes for high-DPI displays
    if scale >= 2.0:  # 4K+ displays
        min_size = 12
    elif scale >= 1.5:  # 1440p+ displays
        min_size = 10
    else:  # 1080p and below
        min_size = 8

    return max(min_size, scaled_size)

def test_scaling_info():
    """Test function to display current scaling information - useful for debugging"""
    try:
        scale = get_scale_factor()

        # Get screen info
        import ctypes
        try:
            user32 = ctypes.windll.user32
            screen_width = user32.GetSystemMetrics(0)
            screen_height = user32.GetSystemMetrics(1)

            # Get DPI info
            dc = user32.GetDC(0)
            dpi_x = ctypes.windll.gdi32.GetDeviceCaps(dc, 88)
            dpi_y = ctypes.windll.gdi32.GetDeviceCaps(dc, 90)
            user32.ReleaseDC(0, dc)
        except:
            screen_width = screen_height = dpi_x = dpi_y = "Unknown"

        info = f"""
Scaling Information:
- Scale Factor: {scale:.2f}
- Screen Resolution: {screen_width}x{screen_height}
- DPI: {dpi_x}x{dpi_y}
- Sample Font Sizes: 12pt -> {get_qt_scaled_font_size(12)}pt, 16pt -> {get_qt_scaled_font_size(16)}pt
- Sample Window Size: 600x400 -> {get_qt_scaled_size(600, 400)}
"""
        print(info)
        logging.info(f"Scaling test - Factor: {scale:.2f}, Resolution: {screen_width}x{screen_height}")
        return info
    except Exception as e:
        error_msg = f"Error testing scaling: {e}"
        print(error_msg)
        logging.error(error_msg)
        return error_msg

# === Multi-Language Support ===
TRANSLATIONS = {
    "en": {  # English
        "app_title": "Star Citizen Kill Tracker",
        "main_menu": "Main Menu",
        "settings": "Settings",
        "support": "Support",
        "about": "About",
        "welcome": "Welcome",
        "version": "Version",
        "game_version": "SC Game Version",
        "quick_actions": "Quick Actions",
        "send_feedback": "Send Feedback",
        "system_details": "System Details",
        "shortcuts": "Shortcuts",
        "need_help": "Need Help?",
        "overlay_enabled": "Overlay Enabled",
        "overlay_disabled": "Overlay Disabled",
        "auto_hide": "Auto Hide (10 seconds)",
        "awaiting_data": "Awaiting Data",
        "zone": "Zone",
        "victim": "Victim",
        "killer": "Killer",
        "weapon": "Weapon",
        "damage_type": "Damage Type",
        "method": "Method",
        "player": "Player",
        "console": "Console",
        "language": "Language",
        "apply": "Apply",
        "close": "Close",
        "start_tracker": "🚀 Start SC Kill Tracker",
        "join_discord": "💬 Join Discord",
        "visit_website": "🌐 Visit Website",
        "legal_docs": "📄 Legal Docs",
        "restart_app": "🔄 Restart Application",
        "welcome_description": "Track your kills and deaths in Star Citizen with real-time overlay notifications."
    },
    "es": {  # Spanish
        "app_title": "Rastreador de Muertes de Star Citizen",
        "main_menu": "Menú Principal",
        "settings": "Configuración",
        "support": "Soporte",
        "about": "Acerca de",
        "welcome": "Bienvenido",
        "version": "Versión",
        "game_version": "Versión del Juego SC",
        "quick_actions": "Acciones Rápidas",
        "send_feedback": "Enviar Comentarios",
        "system_details": "Detalles del Sistema",
        "shortcuts": "Accesos Directos",
        "need_help": "¿Necesitas Ayuda?",
        "overlay_enabled": "Overlay Habilitado",
        "overlay_disabled": "Overlay Deshabilitado",
        "auto_hide": "Ocultar Automáticamente (10 segundos)",
        "awaiting_data": "Esperando Datos",
        "zone": "Zona",
        "victim": "Víctima",
        "killer": "Asesino",
        "weapon": "Arma",
        "damage_type": "Tipo de Daño",
        "method": "Método",
        "player": "Jugador",
        "console": "Consola",
        "language": "Idioma",
        "apply": "Aplicar",
        "close": "Cerrar",
        "start_tracker": "🚀 Iniciar Rastreador SC",
        "join_discord": "💬 Unirse a Discord",
        "visit_website": "🌐 Visitar Sitio Web",
        "legal_docs": "📄 Documentos Legales",
        "restart_app": "🔄 Reiniciar Aplicación",
        "welcome_description": "Rastrea tus muertes y asesinatos en Star Citizen con notificaciones de overlay en tiempo real."
    },
    "fr": {  # French
        "app_title": "Traqueur de Morts Star Citizen",
        "main_menu": "Menu Principal",
        "settings": "Paramètres",
        "support": "Support",
        "about": "À Propos",
        "welcome": "Bienvenue",
        "version": "Version",
        "game_version": "Version du Jeu SC",
        "quick_actions": "Actions Rapides",
        "send_feedback": "Envoyer des Commentaires",
        "system_details": "Détails du Système",
        "shortcuts": "Raccourcis",
        "need_help": "Besoin d'Aide?",
        "overlay_enabled": "Overlay Activé",
        "overlay_disabled": "Overlay Désactivé",
        "auto_hide": "Masquer Automatiquement (10 secondes)",
        "awaiting_data": "En Attente de Données",
        "zone": "Zone",
        "victim": "Victime",
        "killer": "Tueur",
        "weapon": "Arme",
        "damage_type": "Type de Dégâts",
        "method": "Méthode",
        "player": "Joueur",
        "console": "Console",
        "language": "Langue",
        "apply": "Appliquer",
        "close": "Fermer",
        "start_tracker": "🚀 Démarrer Traqueur SC",
        "join_discord": "💬 Rejoindre Discord",
        "visit_website": "🌐 Visiter le Site Web",
        "legal_docs": "📄 Documents Légaux",
        "restart_app": "🔄 Redémarrer l'Application",
        "welcome_description": "Suivez vos morts et vos éliminations dans Star Citizen avec des notifications d'overlay en temps réel."
    },
    "de": {  # German
        "app_title": "Star Citizen Kill Tracker",
        "main_menu": "Hauptmenü",
        "settings": "Einstellungen",
        "support": "Support",
        "about": "Über",
        "welcome": "Willkommen",
        "version": "Version",
        "game_version": "SC Spielversion",
        "quick_actions": "Schnellaktionen",
        "send_feedback": "Feedback Senden",
        "system_details": "Systemdetails",
        "shortcuts": "Verknüpfungen",
        "need_help": "Hilfe Benötigt?",
        "overlay_enabled": "Overlay Aktiviert",
        "overlay_disabled": "Overlay Deaktiviert",
        "auto_hide": "Automatisch Ausblenden (10 Sekunden)",
        "awaiting_data": "Warten auf Daten",
        "zone": "Zone",
        "victim": "Opfer",
        "killer": "Mörder",
        "weapon": "Waffe",
        "damage_type": "Schadenstyp",
        "method": "Methode",
        "player": "Spieler",
        "console": "Konsole",
        "language": "Sprache",
        "apply": "Anwenden",
        "close": "Schließen",
        "start_tracker": "🚀 SC Tracker Starten",
        "join_discord": "💬 Discord Beitreten",
        "visit_website": "🌐 Website Besuchen",
        "legal_docs": "📄 Rechtsdokumente",
        "restart_app": "🔄 Anwendung Neustarten",
        "welcome_description": "Verfolgen Sie Ihre Todesfälle und Kills in Star Citizen mit Echtzeit-Overlay-Benachrichtigungen."
    }
}

# Current language setting
CURRENT_LANGUAGE = "en"

def get_text(key, fallback=None):
    """Get translated text for the current language"""
    global CURRENT_LANGUAGE
    try:
        return TRANSLATIONS[CURRENT_LANGUAGE].get(key, fallback or key)
    except:
        return fallback or key

def set_language(lang_code):
    """Set the current language"""
    global CURRENT_LANGUAGE
    if lang_code in TRANSLATIONS:
        CURRENT_LANGUAGE = lang_code
        # Save language preference
        try:
            os.makedirs(SETTINGS_DIR, exist_ok=True)
            with open(USER_LANGUAGE_FILE, "w") as f:
                json.dump({"language": lang_code}, f)
        except Exception as e:
            logging.warning(f"Failed to save language preference: {e}")

def load_user_language():
    """Load user's language preference"""
    global CURRENT_LANGUAGE
    try:
        if os.path.exists(USER_LANGUAGE_FILE):
            with open(USER_LANGUAGE_FILE, "r") as f:
                data = json.load(f)
                lang = data.get("language", "en")
                if lang in TRANSLATIONS:
                    CURRENT_LANGUAGE = lang
                    return lang
    except Exception as e:
        logging.warning(f"Failed to load language preference: {e}")
    return "en"

# === Monitoring Logic ===

def monitor_log():
    global running
    while running:
        flags = fetch_remote_flags()

        if flags["disable_client"]:
            logging.info("Client disabled by remote flag.")
            running = False
            break

        if flags["mandatory_update"]:
            logging.warning("Update required.")
            show_mandatory_update_popup(flags["required_version"])
            running = False
            break

        logging.info("Monitoring log file...")
        time.sleep(60)


if "disablewebhook" in startup_flag:
    print("Discord webhooks/relays are disabled by startup flag.")
    ENABLE_DISCORD_WEBHOOKS = False
else:
    ENABLE_DISCORD_WEBHOOKS = True

# === Font Management ===
# === Font Installation ===

def check_if_installed():
    return os.path.exists(FONT_PATH)

def download_zip():
    try:
        response = requests.get(FONT_URL)
        response.raise_for_status()
        with open(FONT_ZIP_PATH, 'wb') as f:
            f.write(response.content)
        return True
    except requests.RequestException as e:
        logging.error(f"Download failed: {e}")
        return False

def extract_font():
    try:
        with zipfile.ZipFile(FONT_ZIP_PATH, 'r') as zip_ref:
            zip_ref.extractall(FONT_FOLDER)
        return True
    except zipfile.BadZipFile as e:
        logging.error(f"Extraction failed: {e}")
        return False

def install_font():
    if check_if_installed():
        logging.info(f"{FONT_NAME} already installed.")
        return

    logging.info(f"Installing font: {FONT_NAME}")
    if not download_zip() or not extract_font():
        return

    try:
        shutil.copy(FONT_PATH, FONT_FOLDER)
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts",
            0, winreg.KEY_WRITE
        ) as key:
            winreg.SetValueEx(key, FONT_NAME, 0, winreg.REG_SZ, FONT_PATH)
        logging.info(f"{FONT_NAME} registered successfully.")
    except Exception as e:
        logging.error(f"Font registration failed: {e}")

if not check_if_installed():
    install_font()

# === Asset Handling ===

def get_local_logo_path():
    base_path = Path("C:/Program Files/Harley's Studio/Star Citizen Kill Tracker/assets")
    base_path.mkdir(parents=True, exist_ok=True)
    return base_path / "logo.png"

def download_logo_if_needed():
    path = get_local_logo_path()
    if not path.exists():
        try:
            response = requests.get(LOGO_URL, timeout=10)
            response.raise_for_status()
            with open(path, 'wb') as f:
                f.write(response.content)
            logging.info(f"Logo downloaded to {path}")
        except Exception as e:
            logging.error(f"Failed to download logo: {e}")
            return None
    return path

app_logo_tk = None  # For Tkinter
app_logo_qt = None  # For PySide6
from PySide6.QtGui import QPixmap
from PySide6.QtCore import QByteArray
from PySide6.QtCore import QBuffer, QIODevice

def load_global_logo() -> QPixmap | None:
    global app_logo_tk, app_logo_qt
    try:
        response = requests.get(LOGO_URL)
        response.raise_for_status()
        image_data = response.content

        # --- Tkinter version ---
        pil_image = Image.open(BytesIO(image_data))
        app_logo_tk = ImageTk.PhotoImage(pil_image)

        # --- Qt version ---
        byte_array = QByteArray(image_data)
        app_logo_qt = QPixmap()
        if not app_logo_qt.loadFromData(byte_array):
            logging.warning("QPixmap failed to load from data.")
            return None

        logging.info("Global logo loaded for both Tkinter and Qt.")
        return app_logo_qt

    except Exception as e:
        logging.error(f"Failed to load logo image: {e}", exc_info=True)
        return None


def is_user_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
    
def run_as_admin(extra_args=None):
    """
    Relaunch the current script with admin privileges.
    Shows a dialog to confirm with the user.
    """
    if os.name != 'nt':
        logging.warning("Admin elevation only supported on Windows.")
        return False

    # Ensure QApplication is initialized
    if QApplication.instance() is None:
        _ = QApplication(sys.argv)

    # Ask user if they want to elevate
    dialog = QDialog()
    dialog.setWindowTitle("Admin Privileges Required")
    dialog.setWindowModality(Qt.ApplicationModal)
    # Use scaled size for better high-DPI support
    scaled_width, scaled_height = get_qt_scaled_size(600, 300)
    dialog.setFixedSize(scaled_width, scaled_height)
    # Make dialog stay on top
    dialog.setWindowFlags(
        Qt.Dialog |
        Qt.WindowStaysOnTopHint |
        Qt.WindowSystemMenuHint |
        Qt.WindowTitleHint |
        Qt.WindowCloseButtonHint
    )

    # Logo
    logo_label = QLabel()
    pixmap = load_global_logo()
    if pixmap and not pixmap.isNull():
        scaled = pixmap.scaled(128, 128, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(scaled)
        dialog.setWindowIcon(QIcon(scaled))
    logo_label.setAlignment(Qt.AlignCenter)

    # Message
    message = QLabel(
        "This application requires administrator privileges to function properly.\n\n"
        "Do you want to restart with elevated permissions?"
    )
    message.setWordWrap(True)
    message.setAlignment(Qt.AlignCenter)

    # Buttons
    yes_button = QPushButton("Yes")
    no_button = QPushButton("No")

    button_layout = QHBoxLayout()
    button_layout.addWidget(yes_button)
    button_layout.addWidget(no_button)

    layout = QVBoxLayout()
    layout.addWidget(logo_label)
    layout.addWidget(message)
    layout.addLayout(button_layout)
    dialog.setLayout(layout)

    # Connect
    yes_button.clicked.connect(dialog.accept)
    no_button.clicked.connect(dialog.reject)

    result = dialog.exec()

    if result == QDialog.Accepted:
        try:
            script = os.path.abspath(sys.argv[0])
            params = [f'"{arg}"' for arg in sys.argv[1:] if arg != "--elevated"]
            if extra_args:
                for arg in extra_args:
                    if f'"{arg}"' not in params:
                        params.append(f'"{arg}"')

            param_str = " ".join(params)

            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script}" {param_str}', None, 1
            )
            return ret > 32
        except Exception as e:
            logging.error(f"Failed to elevate privileges: {e}")
            return False
    else:
        # Warning dialog
        warning = QDialog()
        warning.setWindowTitle("Warning")
        # Use scaled size for better high-DPI support
        scaled_width, scaled_height = get_qt_scaled_size(600, 300)
        warning.setFixedSize(scaled_width, scaled_height)
        # Make warning dialog stay on top
        warning.setWindowFlags(
            Qt.Dialog |
            Qt.WindowStaysOnTopHint |
            Qt.WindowSystemMenuHint |
            Qt.WindowTitleHint |
            Qt.WindowCloseButtonHint
        )
        if pixmap and not pixmap.isNull():
            warning.setWindowIcon(QIcon(pixmap))

        warning_layout = QVBoxLayout()
        warning_text = (
            "⚠️ Warning: This application requires administrator privileges to run.\n\n"
            "Without elevated permissions, the application will not function and must be restarted "
            "with administrator rights.\n\n"
            "Please restart the application with the required permissions to ensure full functionality."
        )
        warning_label = QLabel(warning_text)
        warning_label.setWordWrap(True)
        warning_label.setAlignment(Qt.AlignCenter)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(warning.accept)

        warning_layout.addWidget(warning_label)
        warning_layout.addWidget(ok_button, alignment=Qt.AlignCenter)
        warning.setLayout(warning_layout)
        warning.exec()
        return False
    
import win32com.client

def create_shortcut():
    """Create a shortcut from Program Files to LocalAppData."""
    try:
        target = os.path.expandvars(r"%LocalAppData%\Harley's Studio\Star Citizen Kill Tracker")
        shortcut_path = r"C:\Program Files\Harley's Studio\Star Citizen Kill Tracker\SCKillTrac[LocalAppData].lnk"

        # Ensure target exists (optional)
        os.makedirs(os.path.dirname(target), exist_ok=True)

        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortcut(shortcut_path)
        shortcut.TargetPath = target
        shortcut.WorkingDirectory = target
        shortcut.WindowStyle = 1
        shortcut.Description = "Shortcut to Kill Tracker Data"
        shortcut.Save()

        print(f"Shortcut created at: {shortcut_path}")
        return True
    except Exception as e:
        print(f"Failed to create shortcut: {e}")
        logging.error(f"Failed to create shortcut: {e}")
        return False

from PySide6.QtCore import Qt, QSize, QPropertyAnimation, QEasingCurve, QTimer
from PySide6.QtWidgets import (
    QApplication, QDialog, QLabel, QPushButton, QHBoxLayout, QVBoxLayout,
    QGraphicsOpacityEffect
)
from PySide6.QtGui import QIcon, QPixmap, QDesktopServices
from PySide6.QtCore import QUrl
from PySide6.QtCore import QEvent, QPropertyAnimation, QEasingCurve
from PySide6.QtWidgets import QGraphicsOpacityEffect


class HoverAnimator(QObject):
    def __init__(self, widget, duration=300):
        super().__init__(widget)
        self.widget = widget
        self.duration = duration
        self.effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(self.effect)
        self.anim = QPropertyAnimation(self.effect, b"opacity")
        self.anim.setDuration(duration)
        self.anim.setEasingCurve(QEasingCurve.InOutCubic)
        self.effect.setOpacity(1.0)  # start fully opaque

    def eventFilter(self, watched, event):
        if watched == self.widget:
            if event.type() == QEvent.Enter:
                # Fade to 0.7 opacity on hover
                self.anim.stop()
                self.anim.setStartValue(self.effect.opacity())
                self.anim.setEndValue(0.7)
                self.anim.start()
            elif event.type() == QEvent.Leave:
                # Fade back to full opacity when not hovered
                self.anim.stop()
                self.anim.setStartValue(self.effect.opacity())
                self.anim.setEndValue(1.0)
                self.anim.start()
        return super().eventFilter(watched, event)

from PySide6.QtWidgets import QTextBrowser
import requests
import markdown

def show_welcome_screen():
    # Fetch remote flags from client.json
    flags = {
        "disable_client": False,
        "mandatory_update": False,
        "version": VERSION  # default local version
    }

    try:
        url = "https://raw.githubusercontent.com/HarleyTG-O/sc-killfeed/main/client.json"
        with urllib.request.urlopen(url) as response:
            data = json.load(response)
            flags["disable_client"] = data.get("disable_client", False)
            flags["mandatory_update"] = data.get("mandatory_update", False)
            flags["version"] = data.get("version", VERSION)
    except Exception as e:
        logging.warning(f"Failed to fetch remote client flags: {e}")
        # Proceed with defaults if fetch fails

    if flags["disable_client"]:
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Critical)
        msg_box.setWindowTitle("Client Disabled")
        msg_box.setText(
            "This client has been disabled by the developer.\n"
            "Please visit the official site for more info."
        )

        # Load and set your logo as window icon
        pixmap = load_global_logo()
        if pixmap and not pixmap.isNull():
            scaled = pixmap.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            msg_box.setWindowIcon(QIcon(scaled))
        else:
            logging.warning("Global logo failed to load for client disabled message.")

        msg_box.exec()
        return  # Exit early, don't show welcome screen


    # If mandatory update required or remote version is newer, show update popup
    if flags["mandatory_update"] or compare_versions(flags["version"], VERSION):
        show_mandatory_update_popup(flags["version"])
        return  # Exit early
    
    def save_user_language(lang_code: str):
        os.makedirs(SETTINGS_DIR, exist_ok=True)
        with open(USER_LANGUAGE_FILE, "w") as f:
            json.dump({"language": lang_code}, f)

    def get_user_language(default: str = "EN-US") -> str:
        try:
            if os.path.exists(USER_LANGUAGE_FILE):
                with open(USER_LANGUAGE_FILE, "r") as f:
                    data = json.load(f)
                    return data.get("language", default)
        except Exception:
            pass
        return default

    app = QApplication.instance() or QApplication(sys.argv)

    # Load user language preference
    load_user_language()

    dialog = QDialog()
    dialog.setWindowTitle(f"{get_text('welcome')} - {get_text('app_title')}")
    dialog.setWindowModality(Qt.ApplicationModal)
    # Use scaled size for better high-DPI support
    scaled_width, scaled_height = get_qt_scaled_size(600, 500)
    dialog.setFixedSize(scaled_width, scaled_height)
    # Make dialog stay on top with proper flags
    dialog.setWindowFlags(
        Qt.Dialog |
        Qt.WindowStaysOnTopHint |
        Qt.WindowSystemMenuHint |
        Qt.WindowTitleHint |
        Qt.WindowCloseButtonHint
    )
    dialog.setAttribute(Qt.WA_ShowWithoutActivating, False)  # Ensure it gets focus

    # --- Logo ---
    logo_label = QLabel()
    pixmap = load_global_logo()
    if pixmap and not pixmap.isNull():
        scaled = pixmap.scaled(128, 128, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(scaled)
        dialog.setWindowIcon(QIcon(scaled))
    else:
        logging.warning("Global logo failed to load.")
    logo_label.setAlignment(Qt.AlignCenter)

    # --- Welcome Text ---
    welcome_label = QLabel(f"""
        <h2 style='color: #00bfff; text-align: center;'>{get_text('Welcome to')} {get_text('app_title')}</h2>
        <p style='color: white; text-align: center; font-size: 16px;'>
            
        </p>
        <p style='color: #ccc; text-align: center;'>
            {get_text('welcome_description')}
        </p>
        <p style='color: #888; text-align: center; font-size: 12px;'>
            <i>[{get_text('version')}: {VERSION} - {BUILD_TYPE} ({DEPLOYMENT_SCOPE})]</i>
        </p>
    """)
    welcome_label.setAlignment(Qt.AlignCenter)
    welcome_label.setWordWrap(True)

    # --- Main Buttons ---
    continue_button = QPushButton(get_text("start_tracker"))
    continue_button.setMinimumHeight(55)
    # Use scaled font size for better high-DPI support
    scaled_font_size = get_qt_scaled_font_size(20)
    continue_button.setStyleSheet(
        f"font-size: {scaled_font_size}px; font-weight: bold; padding: 12px 30px;"
        "background-color: #00bfff; color: white; border-radius: 8px;"
    )
    continue_button.setDefault(True)
    continue_button.setFixedWidth(320)

    discord_button = QPushButton(get_text("join_discord"))
    # Use scaled font sizes and widths for better high-DPI support
    scaled_button_font = get_qt_scaled_font_size(14)
    scaled_button_width = int(150 * get_scale_factor())

    discord_button.setStyleSheet(
        f"font-size: {scaled_button_font}px; padding: 10px 20px; border-radius: 6px;"
        "background-color: #7289da; color: white;"
    )
    discord_button.setFixedWidth(scaled_button_width)

    website_button = QPushButton(get_text("visit_website"))
    website_button.setStyleSheet(
        f"font-size: {scaled_button_font}px; padding: 10px 20px; border-radius: 6px;"
        "background-color: #4caf50; color: white;"
    )
    website_button.setFixedWidth(scaled_button_width)

    # --- Legal Docs Dropdown ---
    legal_button = QPushButton(get_text("legal_docs"))
    legal_button.setStyleSheet(
        f"font-size: {scaled_button_font}px; padding: 10px 20px; border-radius: 6px;"
        "background-color: #888; color: white;"
    )
    legal_button.setFixedWidth(scaled_button_width)

    menu = QMenu(legal_button)
    menu.addAction("📄 Terms of Service", lambda: show_legal_dialog("Terms of Service", "https://raw.githubusercontent.com/HarleyTG-O/sc-killfeed/main/tos-sckt.md"))
    menu.addAction("📄 Privacy Policy", lambda: show_legal_dialog("Privacy Policy", "https://raw.githubusercontent.com/HarleyTG-O/sc-killfeed/main/privacy-sckt.md"))
    menu.addAction("📄 View License", lambda: show_legal_dialog("License", "https://raw.githubusercontent.com/HarleyTG-O/sc-killfeed/main/eula-sckt.md"))
    menu.addAction("📄 View EULA", lambda: show_legal_dialog("EULA", "https://raw.githubusercontent.com/HarleyTG-O/sc-killfeed/main/EULA.md"))
    legal_button.setMenu(menu)

    # --- Language Settings Side Panel ---
    settings_panel = QWidget(dialog)
    settings_panel.setFixedSize(250, 200)
    settings_panel.setStyleSheet("""
        QWidget {
            background-color: rgba(40, 40, 40, 240);
            border: 2px solid #555;
            border-radius: 10px;
        }
    """)

    # Add drop shadow effect to the panel
    try:
        shadow_effect = QGraphicsDropShadowEffect()
        shadow_effect.setBlurRadius(15)
        shadow_effect.setColor(QColor(0, 0, 0, 160))
        shadow_effect.setOffset(3, 3)
        settings_panel.setGraphicsEffect(shadow_effect)
    except Exception as e:
        logging.warning(f"Could not add shadow effect to settings panel: {e}")

    settings_panel.hide()  # Initially hidden

    # Settings panel layout
    settings_layout = QVBoxLayout(settings_panel)
    settings_layout.setContentsMargins(15, 15, 15, 15)
    settings_layout.setSpacing(10)

    # Settings title
    settings_title = QLabel(f"⚙️ {get_text('settings')}")
    settings_title.setStyleSheet(f"color: white; font-size: {scaled_button_font + 2}px; font-weight: bold;")
    settings_title.setAlignment(Qt.AlignCenter)
    settings_layout.addWidget(settings_title)

    # Language section
    language_label = QLabel(get_text("language") + ":")
    language_label.setStyleSheet(f"color: white; font-size: {scaled_button_font}px;")
    settings_layout.addWidget(language_label)

    language_combo = QComboBox()
    language_combo.addItem("🇺🇸 English", "en")
    language_combo.addItem("🇪🇸 Español", "es")
    language_combo.addItem("🇫🇷 Français", "fr")
    language_combo.addItem("🇩🇪 Deutsch", "de")

    # Set current language as selected
    for i in range(language_combo.count()):
        if language_combo.itemData(i) == CURRENT_LANGUAGE:
            language_combo.setCurrentIndex(i)
            break

    language_combo.setStyleSheet(f"""
        QComboBox {{
            font-size: {scaled_button_font}px;
            padding: 8px 12px;
            border-radius: 6px;
            background-color: #555;
            color: white;
            border: 1px solid #777;
            min-height: 20px;
        }}
        QComboBox:hover {{
            background-color: #666;
            border: 1px solid #888;
        }}
        QComboBox:focus {{
            border: 2px solid #0078d7;
        }}
        QComboBox::drop-down {{
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 25px;
            border-left-width: 1px;
            border-left-color: #777;
            border-left-style: solid;
            border-top-right-radius: 6px;
            border-bottom-right-radius: 6px;
            background-color: #666;
        }}
        QComboBox::drop-down:hover {{
            background-color: #777;
        }}
        QComboBox::down-arrow {{
            width: 0;
            height: 0;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 5px solid white;
            margin: 0px;
        }}
        QComboBox::down-arrow:hover {{
            border-top: 5px solid #ccc;
        }}
        QComboBox QAbstractItemView {{
            background-color: #555;
            color: white;
            selection-background-color: #0078d7;
            selection-color: white;
            border: 1px solid #777;
            outline: none;
        }}
        QComboBox QAbstractItemView::item {{
            padding: 4px;
            border: none;
        }}
        QComboBox QAbstractItemView::item:hover {{
            background-color: #666;
        }}
        QComboBox QAbstractItemView::item:selected {{
            background-color: #0078d7;
        }}
    """)
    settings_layout.addWidget(language_combo)

    # Close button for settings panel
    close_settings_btn = QPushButton("✕ " + get_text("close"))
    close_settings_btn.setStyleSheet(f"""
        QPushButton {{
            font-size: {scaled_button_font}px;
            padding: 6px 12px;
            border-radius: 4px;
            background-color: #666;
            color: white;
            border: none;
        }}
        QPushButton:hover {{
            background-color: #777;
        }}
        QPushButton:pressed {{
            background-color: #555;
        }}
    """)
    settings_layout.addWidget(close_settings_btn)
    settings_layout.addStretch()

    def on_language_changed():
        selected_lang = language_combo.currentData()
        if selected_lang and selected_lang != CURRENT_LANGUAGE:
            set_language(selected_lang)
            # Update all text elements immediately
            dialog.setWindowTitle(f"{get_text('welcome')} - {get_text('app_title')}")
            continue_button.setText(get_text("start_tracker"))
            discord_button.setText(get_text("join_discord"))
            website_button.setText(get_text("visit_website"))
            legal_button.setText(get_text("legal_docs"))
            language_label.setText(get_text("language") + ":")
            settings_title.setText(f"⚙️ {get_text('settings')}")
            close_settings_btn.setText("✕ " + get_text("close"))
            welcome_label.setText(f"""
                <h2 style='color: #00bfff; text-align: center;'>{get_text('welcome')}</h2>
                <p style='color: white; text-align: center; font-size: 16px;'>
                    {get_text('app_title')} {VERSION}
                </p>
                <p style='color: #ccc; text-align: center;'>
                    {get_text('welcome_description')}
                </p>
                <p style='color: #888; text-align: center; font-size: 12px;'>
                    <i>[{get_text('version')}: {VERSION} - {BUILD_TYPE} ({DEPLOYMENT_SCOPE})]</i>
                </p>
            """)

    # Connect the language combo box to its event handler
    language_combo.currentIndexChanged.connect(on_language_changed)

    # Settings gear button (child of dialog)
    settings_gear_btn = QPushButton("⚙️", dialog)
    settings_gear_btn.setFixedSize(40, 40)
    settings_gear_btn.setStyleSheet(f"""
        QPushButton {{
            font-size: 20px;
            border-radius: 20px;
            background-color: rgba(60, 60, 60, 180);
            color: white;
            border: 2px solid #777;
        }}
        QPushButton:hover {{
            background-color: rgba(80, 80, 80, 200);
            border: 2px solid #999;
        }}
        QPushButton:pressed {{
            background-color: rgba(40, 40, 40, 200);
        }}
    """)
    settings_gear_btn.setToolTip(get_text("settings"))

    def toggle_settings_panel():
        if settings_panel.isVisible():
            # Fade out and hide
            settings_panel.hide()
        else:
            # Position the panel to the left of the gear button
            gear_pos = settings_gear_btn.pos()
            panel_x = gear_pos.x() - settings_panel.width() - 10
            panel_y = gear_pos.y()

            # Keep panel within dialog bounds
            if panel_x < 10:
                panel_x = 10
            if panel_y + settings_panel.height() > dialog.height():
                panel_y = dialog.height() - settings_panel.height() - 10

            settings_panel.move(panel_x, panel_y)
            settings_panel.show()
            settings_panel.raise_()

    def close_settings_panel():
        settings_panel.hide()

    settings_gear_btn.clicked.connect(toggle_settings_panel)
    close_settings_btn.clicked.connect(close_settings_panel)

    # --- Button Layout ---
    button_layout = QHBoxLayout()
    button_layout.setSpacing(20)
    button_layout.addWidget(discord_button)
    button_layout.addWidget(website_button)
    button_layout.addWidget(legal_button)

    # --- Layout ---
    layout = QVBoxLayout()
    layout.setContentsMargins(40, 20, 40, 20)
    layout.setSpacing(15)
    layout.addWidget(logo_label)
    layout.addWidget(welcome_label)
    layout.addLayout(button_layout)
    layout.addWidget(continue_button, alignment=Qt.AlignCenter)
    dialog.setLayout(layout)

    # Position settings gear button in top-right corner
    def position_settings_button():
        dialog.update()  # Ensure dialog is properly sized
        gear_x = dialog.width() - settings_gear_btn.width() - 15
        gear_y = 15
        settings_gear_btn.move(gear_x, gear_y)
        settings_gear_btn.raise_()  # Bring to front

    # Position the gear button after dialog is shown
    dialog.show()
    position_settings_button()

    # Reposition gear button if dialog is resized
    def on_dialog_resize():
        position_settings_button()

    dialog.resizeEvent = lambda event: (QDialog.resizeEvent(dialog, event), on_dialog_resize())

    # --- Event Handlers ---
    class DiscordChoiceDialog(QDialog):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Discord App or Browser")
            logo_label = QLabel()
            pixmap = load_global_logo()
            if pixmap and not pixmap.isNull():
                scaled = pixmap.scaled(128, 128, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                logo_label.setPixmap(scaled)
                self.setWindowIcon(QIcon(scaled))
            logo_label.setAlignment(Qt.AlignCenter)

            info_label = QLabel(
                "Do you use the Discord desktop app?\n\n"
                "Click 'Discord App' to open in the Discord app.\n"
                "Click 'Discord Web' to open in your web browser."
            )
            info_label.setAlignment(Qt.AlignCenter)
            info_label.setWordWrap(True)

            self.app_button = QPushButton("Discord App")
            self.web_button = QPushButton("Discord Web")

            self.app_button.clicked.connect(self.accept)
            self.web_button.clicked.connect(self.reject)

            btn_layout = QHBoxLayout()
            btn_layout.addWidget(self.app_button)
            btn_layout.addWidget(self.web_button)

            main_layout = QVBoxLayout()
            main_layout.addWidget(logo_label)
            main_layout.addWidget(info_label)
            main_layout.addLayout(btn_layout)
            self.setLayout(main_layout)

    def open_discord():
        invite_url = "https://discord.gg/jxfHnGQqj7"
        browser_url = "https://discord.com/channels/1367284397400785027/1367289292854005800/1367296671570067517"
        client_url = "discord://discord.com/channels/1367284397400785027/1367289292854005800/1367296671570067517"

        dialog_dc = DiscordChoiceDialog()
        result = dialog_dc.exec()

        if result != QDialog.Accepted:
            return

        in_server = QMessageBox.question(
            None,
            "In Server?",
            "Are you already a member of the Star Citizen Kill Tracker Discord server?",
            QMessageBox.Yes | QMessageBox.No
        )

        if in_server == QMessageBox.No:
            QDesktopServices.openUrl(QUrl(invite_url))
            QMessageBox.information(None, "Join First", "Please join the server first, then try again.")
            return

        QDesktopServices.openUrl(QUrl(client_url))

    def open_website():
        try:
            with urllib.request.urlopen("https://raw.githubusercontent.com/HarleyTG-O/sc-killfeed/main/website.json") as response:
                data = json.load(response)
                url = data.get("url")
                if url:
                    QDesktopServices.openUrl(QUrl(url))
                else:
                    print("URL not found in JSON.")
        except Exception as e:
            print(f"Failed to load website URL: {e}")

    def show_legal_dialog(title: str, url: str):
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            md_text = resp.text
            html = markdown.markdown(md_text, extensions=["extra", "sane_lists"])
        except Exception as e:
            html = f"<h2>Error loading {title}</h2><p>{e}</p>"

        popup = QDialog(dialog)
        popup.setWindowTitle(title)
        popup.setMinimumSize(600, 500)
        layout = QVBoxLayout(popup)
        browser = QTextBrowser()
        browser.setHtml(html)
        layout.addWidget(browser)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(popup.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)
        popup.exec()

    def handle_continue():
        dialog.accept()

    discord_button.clicked.connect(open_discord)
    website_button.clicked.connect(open_website)
    continue_button.clicked.connect(handle_continue)

    # --- Hover animations ---
    # Assuming you have a HoverAnimator class; if not, remove this block
    hover_animations = []
    for btn in (continue_button, discord_button, website_button, legal_button):
        animator = HoverAnimator(btn)
        btn.installEventFilter(animator)
        hover_animations.append(animator)
    dialog.hover_animations = hover_animations

    return dialog.exec()

# Directories
USER_DIR = os.path.join(os.getenv('LOCALAPPDATA'), "Harley's Studio", "Star Citizen Kill Tracker", "User")
os.makedirs(USER_DIR, exist_ok=True)

KEY_FILE = os.path.join(USER_DIR, ".enc_key")
SALT_FILE = os.path.join(USER_DIR, ".enc_salt")

# ---------- ENCRYPTION UTILITIES ----------

def generate_and_store_key():
    if os.path.exists(KEY_FILE) and os.path.exists(SALT_FILE):
        return

    salt = get_random_bytes(32)
    password = get_random_bytes(32)
    key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA512)

    with open(KEY_FILE, 'wb') as f: f.write(key)
    with open(SALT_FILE, 'wb') as f: f.write(salt)

def load_encryption_key():
    if not os.path.exists(KEY_FILE) or not os.path.exists(SALT_FILE):
        generate_and_store_key()
    with open(KEY_FILE, 'rb') as f:
        return f.read()

def encrypt_data(data: dict, key: bytes) -> bytes:
    raw = json.dumps(data).encode("utf-8")
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(pad(raw, AES.block_size))
    return iv + tag + ct

def decrypt_data(enc: bytes, key: bytes) -> dict:
    iv = enc[:16]
    tag = enc[16:32]
    ct = enc[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    raw = unpad(cipher.decrypt_and_verify(ct, tag), AES.block_size)
    return json.loads(raw.decode("utf-8"))

# ---------- USER HANDLING ----------

def user_registered():
    return bool(glob.glob(os.path.join(USER_DIR, "*_id.enc")))

def get_user_file_path(name: str):
    return os.path.join(USER_DIR, f"{name}_id.enc")

def create_id_file(name: str, key: bytes) -> str:
    user_data = {
        "Username": name,
        "SCKillTrac ID": f"{name}@SCKillTrac",
        "UUID": f"{name} - SCKillTrac - {uuid.uuid4()}"
    }

    encrypted = encrypt_data(user_data, key)
    file_path = get_user_file_path(name)
    with open(file_path, "wb") as f:
        f.write(encrypted)

    return file_path

def load_first_user_data(key: bytes):
    for file in os.listdir(USER_DIR):
        if file.endswith("_id.enc"):
            with open(os.path.join(USER_DIR, file), "rb") as f:
                return decrypt_data(f.read(), key)
    return None

# ---------- DISCORD WEBHOOK ----------

import time

# Global variable to track last webhook send times (prevent spam)
_last_webhook_times = {}

def send_user_registration_webhook(user_data: dict, login=False, keyauth=False):
    if not all(k in user_data for k in ("Username", "SCKillTrac ID", "UUID")):
        return

    # Prevent duplicate webhooks within 10 seconds
    webhook_key = f"reg_{user_data['Username']}_{login}_{keyauth}"
    current_time = time.time()

    if webhook_key in _last_webhook_times:
        if current_time - _last_webhook_times[webhook_key] < 10:
            logging.info(f"Skipping duplicate registration webhook for {user_data['Username']}")
            return

    _last_webhook_times[webhook_key] = current_time

    try:
        # Enhanced embed for KeyAuth users
        auth_type = "🔐 KeyAuth" if keyauth else "🏠 Local"
        title_prefix = "🆕 New" if not login else "🔑"

        embed = {
            "title": f"{title_prefix} SC Kill Tracker {'Registration' if not login else 'Login'} ({auth_type})",
            "color": 0x00ff00 if keyauth else 0x00bfff,
            "fields": [
                {"name": "Username", "value": user_data["Username"], "inline": False},
                {"name": "SCKillTrac ID", "value": user_data["SCKillTrac ID"], "inline": False},
                {"name": "UUID/HWID", "value": user_data["UUID"], "inline": False},
                {"name": "Authentication", "value": auth_type, "inline": True},
            ],
            "footer": {"text": f"SC Kill Tracker [Version: {VERSION}-{BUILD_TYPE}({DEPLOYMENT_SCOPE})]"}
        }

        # Add KeyAuth-specific fields
        if keyauth and user_data.get("KeyAuth_User"):
            if user_data.get("IP"):
                embed["fields"].append({"name": "IP Address", "value": user_data["IP"], "inline": True})
            if user_data.get("Subscription"):
                embed["fields"].append({"name": "Subscription", "value": user_data["Subscription"], "inline": True})
            if user_data.get("Expires"):
                embed["fields"].append({"name": "Expires", "value": user_data["Expires"], "inline": True})

        payload = {
            "embeds": [embed],
            "username": "SC Kill Tracker KeyAuth System" if keyauth else "SC Kill Tracker Registration/Login System",
            "avatar_url": "https://github.com/HarleyTG-O/sc-killfeed/blob/main/logo.png?raw=true",
            "content": f"{'User Registered' if not login else 'User Logged In'} via {auth_type}: **{user_data['Username']}**"
        }

        response = requests.post(UserLoginWebhook_URL, json=payload, timeout=5)
        response.raise_for_status()
        logging.info(f"{'Registration' if not login else 'Login'} webhook sent for {user_data['Username']} (KeyAuth: {keyauth})")
    except requests.RequestException as e:
        logging.error(f"Registration/Login webhook failed: {e}")

def send_registration_welcome_webhook(user_data: dict):
    """Welcome webhook - only sent once during initial registration"""
    if not all(k in user_data for k in ("Username", "SCKillTrac ID", "UUID")):
        return

    # Prevent duplicate welcome webhooks
    webhook_key = f"welcome_{user_data['Username']}"
    current_time = time.time()
    
    if webhook_key in _last_webhook_times:
        if current_time - _last_webhook_times[webhook_key] < 60:  # Longer cooldown for welcome
            logging.info(f"Skipping duplicate welcome webhook for {user_data['Username']}")
            return
    
    _last_webhook_times[webhook_key] = current_time

    try:
        embed = {
            "title": f"🎉 Welcome {user_data['Username']} to SC Kill Tracker!",
            "description": (
                f"Thanks for registering!\n\n"
                f"Your SCKillTrac ID is `{user_data['SCKillTrac ID']}`.\n"
                f"Keep tracking your kills and stats in Star Citizen.\n\n"
                f"Enjoy the game! 🚀"
            ),
            "color": 0x00ff00,
            "footer": {"text": f"Version: {VERSION}-{BUILD_TYPE} ({DEPLOYMENT_SCOPE})"},
        }

        payload = {
            "embeds": [embed],
            "username": "SC Kill Tracker Bot",
            "avatar_url": "https://github.com/HarleyTG-O/sc-killfeed/blob/main/logo.png?raw=true",
            "content": f"New user just joined: **{user_data['Username']}**!"
        }

        response = requests.post(UserGlobalWebhook_URL, json=payload, timeout=5)
        response.raise_for_status()
        logging.info(f"Welcome webhook sent for {user_data['Username']}")
    except requests.RequestException as e:
        logging.error(f"Welcome webhook failed: {e}")

def handle_user_login(user_data: dict):
    """Handle existing user login - only sends login webhook"""
    send_user_registration_webhook(user_data, login=True)

def handle_user_registration(user_data: dict):
    """Handle new user registration - sends both registration and welcome webhooks"""
    # Send registration webhook first
    send_user_registration_webhook(user_data, login=False)
    
    # Small delay to prevent webhook rate limiting
    time.sleep(0.5)
    
    # Send welcome webhook
    send_registration_welcome_webhook(user_data)

class RegistrationDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Register for SC Kill Tracker")
        self.setWindowModality(Qt.ApplicationModal)
        # Use scaled size for better high-DPI support
        scaled_width, scaled_height = get_qt_scaled_size(600, 300)
        self.setFixedSize(scaled_width, scaled_height)
        # Make registration dialog stay on top
        self.setWindowFlags(
            Qt.Dialog |
            Qt.WindowStaysOnTopHint |
            Qt.WindowSystemMenuHint |
            Qt.WindowTitleHint |
            Qt.WindowCloseButtonHint
        )

        self._registering = False  # Re-entry guard

        # --- Logo ---
        logo_label = QLabel()
        pixmap = load_global_logo()
        if pixmap and not pixmap.isNull():
            scaled = pixmap.scaled(128, 128, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_label.setPixmap(scaled)
            self.setWindowIcon(QIcon(scaled))
        logo_label.setAlignment(Qt.AlignCenter)

        # --- Message ---
        message = QLabel(
            "Enter a unique username to link with SC Kill Tracker.\n\n"
            "This ID is used for tracking stats and syncing with Discord webhooks."
        )
        message.setWordWrap(True)
        message.setAlignment(Qt.AlignCenter)

        # --- Input ---
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Enter your username")
        self.name_input.setMaxLength(24)
        self.name_input.setAlignment(Qt.AlignCenter)
        self.name_input.setFixedHeight(32)
        self.name_input.returnPressed.connect(self.register_user)
        self.name_input.setFocus()

        # --- Buttons ---
        register_button = QPushButton("Register")
        cancel_button = QPushButton("Cancel")

        button_style = """
        QPushButton {
            background-color: #0078d7;
            color: white;
            font-weight: bold;
            font-size: 14px;
            border-radius: 6px;
            padding: 8px 24px;
        }
        QPushButton:hover {
            background-color: #005a9e;
        }
        QPushButton:pressed {
            background-color: #003e73;
        }
        """

        register_button.setStyleSheet(button_style)
        cancel_button.setStyleSheet(button_style)

        register_button.clicked.connect(self.register_user)
        cancel_button.clicked.connect(self.reject)

        # --- Button Layout ---
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(cancel_button)
        button_layout.addWidget(register_button)
        button_layout.addStretch()

        # --- Main Layout ---
        layout = QVBoxLayout()
        layout.addWidget(logo_label)
        layout.addWidget(message)
        layout.addWidget(self.name_input)
        layout.addStretch()
        layout.addLayout(button_layout)
        self.setLayout(layout)

        # --- Esc key shortcut to cancel ---
        self.shortcut_escape = QShortcut(QKeySequence(Qt.Key_Escape), self)
        self.shortcut_escape.activated.connect(self.reject)

    def register_user(self):
        if self._registering:
            logging.warning("Registration already in progress, ignoring duplicate call")
            return

        self._registering = True
        self.setEnabled(False)  # Disable UI to prevent multiple input

        username = self.name_input.text().strip()

        if not username:
            QMessageBox.warning(self, "Input Error", "Please enter a username!")
            self._registering = False
            self.setEnabled(True)
            return

        if len(username) < 3:
            QMessageBox.warning(self, "Input Error", "Username must be at least 3 characters long.")
            self._registering = False
            self.setEnabled(True)
            return

        if os.path.exists(get_user_file_path(username)):
            QMessageBox.warning(self, "Duplicate", "This username is already registered.")
            self._registering = False
            self.setEnabled(True)
            return

        try:
            logging.info(f"Starting registration process for user: {username}")
            
            key = load_encryption_key()
            path = create_id_file(username, key)
            
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    user_data = decrypt_data(f.read(), key)

                logging.info(f"User data created successfully for: {username}")
                
                # Use the centralized registration handler
                handle_user_registration(user_data)

                QMessageBox.information(self, "Success", f"Welcome, {username}! Your account has been created.")
                logging.info(f"Registration completed successfully for: {username}")
                self.accept()
            else:
                logging.error(f"Failed to create user file for: {username}")
                QMessageBox.critical(self, "Error", "Failed to save user profile.")
        except Exception as e:
            logging.error(f"Registration failed for {username}: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", "An unexpected error occurred during registration.")
        finally:
            self._registering = False
            self.setEnabled(True)

# === Loggers ===

logger = logging.getLogger("allslain.launcher_store")
crypt_logger = logging.getLogger("crypt_sindresorhus_conf")

# === Static AES Key ===

KEY = b"OjPs60LNS7LbbroAuPXDkwLRipgfH6hIFA6wvuBxkg4="

# === Custom Exceptions ===
class LauncherStoreException(Exception):
    pass

# === AES Cryptography Class ===
class CryptSindresorhusConf:
    def __init__(self, key: bytes, iv: bytes):
        self.iv = iv
        crypt_logger.debug("Key:      %d %s", len(key), key.hex())
        crypt_logger.debug("IV:       %d %s", len(iv), iv.hex())

        # Salt is derived from IV's UTF-8 decoded bytes (with replace errors)
        salt = iv.decode(encoding="utf-8", errors="replace").encode()
        crypt_logger.debug("Salt:     %d %s", len(salt), salt.hex())

        # Derive password/key from given key and salt using PBKDF2 (SHA512, 10k rounds)
        self.password = PBKDF2(
            key.decode(errors="ignore"), salt, 32, count=10_000, hmac_hash_module=SHA512
        )
        crypt_logger.debug("Password: %d %s", len(self.password), self.password.hex())

    def encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.password, AES.MODE_CBC, self.iv)
        encrypted = cipher.encrypt(pad(data, 16))
        return self.iv + b":" + encrypted

    def decrypt(self, data: bytes) -> bytes:
        # The first 16 bytes are the IV, skip the colon (1 byte)
        cipher = AES.new(self.password, AES.MODE_CBC, self.iv)
        decrypted = cipher.decrypt(data[17:])
        return unpad(decrypted, 16)

# === Launcher Store Handling ===
def find_launcher_store_path() -> Optional[str]:
    potential_dirs = [
        os.getenv("APPDATA"),
        os.path.expanduser("~\\AppData\\Roaming"),
        os.path.expanduser("~"),
    ]

    for base in filter(None, potential_dirs):
        path = os.path.join(base, "rsilauncher", "launcher store.json")
        if os.path.isfile(path):
            logger.debug(f"Found launcher store at: {path}")
            return path

    logger.warning("Launcher store.json not found. Prompting user to select it manually.")
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    return fd.askopenfilename(
        title="Select launcher store.json",
        filetypes=[("Launcher Store", "launcher store.json")],
    )

def read_launcher_store() -> dict:
    path = find_launcher_store_path()
    if not path:
        raise LauncherStoreException("Launcher store file not provided or found.")

    try:
        with open(path, "rb") as f:
            encrypted_data = f.read()

        if len(encrypted_data) < 16:
            raise LauncherStoreException("Launcher store is corrupted or incomplete")

        crypt = CryptSindresorhusConf(KEY, encrypted_data[:16])
        decrypted = crypt.decrypt(encrypted_data)
        return json.loads(decrypted)

    except OSError as e:
        logger.error(f"Error reading launcher store at {path}: {e}")
        raise LauncherStoreException("Failed to read launcher store") from e

    except json.JSONDecodeError as e:
        logger.error(f"Error decoding launcher store JSON: {e}")
        raise LauncherStoreException("Failed to parse launcher store JSON") from e

def get_log_from_launcher_store() -> Optional[str]:
    try:
        data = read_launcher_store()
        library_available = data["library"]["available"]
        if not library_available:
            logger.debug("No available games in launcher store.")
            return None

        available_sc = next((g for g in library_available if g["id"] == "SC"), None)
        if not available_sc:
            logger.debug("Star Citizen not listed in available games.")
            return None

        available_channels = [ch["id"] for ch in available_sc.get("channels", [])]
        install_dirs = {
            g["channelId"]: g.get("installDir")
            for g in data["library"]["settings"]
            if g["gameId"] == "SC" and g["channelId"] in available_channels
        }

        installed_sc = next((g for g in data["library"]["installed"] if g["id"] == "SC"), None)
        if not installed_sc:
            logger.debug("Star Citizen not installed.")
            return None

        installed_channels = {
            ch["id"]: ch
            for ch in installed_sc.get("channels", [])
            if ch["id"] in available_channels
        }

        files = {}
        for channel_id in available_channels:
            ch = installed_channels.get(channel_id)
            if not ch:
                continue
            library_folder = ch.get("libraryFolder")
            install_folder = ch.get("installDir") or install_dirs.get(channel_id)
            if not library_folder or not install_folder:
                continue

            path = os.path.join(library_folder, install_folder, channel_id, "Game.log")
            try:
                files[path] = os.path.getmtime(path)
            except OSError:
                logger.debug(f"Log file not found: {path}")

        return max(files, key=files.get) if files else None

    except LauncherStoreException as e:
        logger.warning(f"Launcher store error: {e}")
        return None
    except Exception:
        logger.exception("Unexpected error while resolving Game.log")
        return None

# === Fallback Log Location Search ===
def get_log_fallback() -> Optional[str]:
    for path in DEFAULT_LOCATIONS:
        if os.path.isfile(path):
            logger.debug(f"Found Game.log at fallback path: {path}")
            return path
    logger.debug("No Game.log found in fallback locations.")
    return None

# === Manual File Dialog ===
def get_log_manual() -> Optional[str]:
    logger.info("Prompting user to manually select Game.log...")
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    return fd.askopenfilename(
        title="Select Game.log",
        filetypes=[("Game Log", "Game.log")],
    )

# === Config Save/Load ===
def get_saved_log_path() -> Optional[str]:
    if not os.path.isfile(CONFIG_PATH):
        return None
    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)
        path = data.get("game_log_path")
        if path and os.path.isfile(path):
            logger.debug(f"Loaded previously saved Game.log path: {path}")
            return path
    except Exception as e:
        logger.warning(f"Error reading saved config: {e}")
    return None

def save_selected_log_path(path: str) -> None:
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump({"game_log_path": path}, f)

_last_monitored_log = None  # To avoid repeated log spam

def fix_drive_letter_path(path: str) -> str:
    """
    Ensures Windows paths start with e.g. 'C:\\' instead of 'C:' (missing backslash after drive).
    """
    return re.sub(r'^([a-zA-Z]):(?!\\)', r'\1:\\', path)

def extract_channel_from_path(path: str) -> Optional[str]:
    upper = path.upper()
    if "EPTU" in upper:
        return "EPTU"
    elif "PTU" in upper:
        return "PTU"
    elif "LIVE" in upper:
        return "LIVE"
    return None

def get_log() -> Optional[Tuple[str, Optional[str]]]:
    # 1. Check saved config
    saved = get_saved_log_path()
    if saved:
        saved = fix_drive_letter_path(saved)
        saved = os.path.abspath(os.path.normpath(saved))
        logger.info(f"Using saved Game.log path: {saved}")
        return saved, extract_channel_from_path(saved)

    # 2. Check running StarCitizen.exe process
    sc_info = find_starcitizen_exe()
    if sc_info:
        exe_path, version, channel = sc_info
        if exe_path and channel:
            base_dir = os.path.abspath(os.path.normpath(os.path.dirname(os.path.dirname(exe_path))))
            base_dir = fix_drive_letter_path(base_dir)

            log_path = os.path.join(base_dir, channel, "Game.log")
            log_path = fix_drive_letter_path(log_path)

            # Fix duplicated channel folder like ...\PTU\PTU\Game.log
            parts = log_path.replace('/', '\\').split('\\')
            if (len(parts) >= 4 and
                parts[-3].upper() == parts[-2].upper() == channel.upper() and
                parts[-1].lower() == "game.log"):
                fixed_parts = parts[:-3] + [channel, parts[-1]]
                log_path = os.path.join(*fixed_parts)
                log_path = fix_drive_letter_path(log_path)

            log_path = os.path.abspath(os.path.normpath(log_path))
            if os.path.isfile(log_path):
                # Use start_monitoring_log to avoid spam
                start_monitoring_log(log_path, channel)
                return log_path, channel
            else:
                logger.warning(f"Expected Game.log for '{channel}' at {log_path} not found.")

    # 3. Check launcher store
    launcher_log = get_log_from_launcher_store()
    if launcher_log:
        launcher_log = fix_drive_letter_path(launcher_log)
        launcher_log = os.path.abspath(os.path.normpath(launcher_log))
        logger.info(f"Game.log found via launcher store: {launcher_log}")
        return launcher_log, extract_channel_from_path(launcher_log)

    # 4. Check hardcoded default paths
    for path in DEFAULT_PTU_LOCATIONS + DEFAULT_EPTU_LOCATIONS + DEFAULT_LOCATIONS:
        normalized_path = fix_drive_letter_path(path)
        normalized_path = os.path.abspath(os.path.normpath(normalized_path))
        if os.path.isfile(normalized_path):
            logger.info(f"Found Game.log in default install locations: {normalized_path}")
            return normalized_path, extract_channel_from_path(normalized_path)

    # 5. Manual fallback
    manual_path = get_log_manual()
    if manual_path:
        manual_path = fix_drive_letter_path(manual_path)
        manual_path = os.path.abspath(os.path.normpath(manual_path))
        if os.path.isfile(manual_path):
            logger.info(f"User manually selected Game.log: {manual_path}")
            save_selected_log_path(manual_path)
            return manual_path, extract_channel_from_path(manual_path)

    logger.error("Failed to resolve Game.log file from all known methods.")
    return None

_last_monitored_log = None  # Global or module-level variable

monitoring = False
log_monitor_thread = None

def handle_log_line(line: str):
    # Your existing log line processing function
    logger.info(f"Log line: {line}")  # Placeholder

def start_monitoring_log(log_path: str, channel: str | None = None) -> None:
    """
    Starts or restarts the log monitor if the path or channel has changed.
    Avoids repeated spam by tracking the last monitored path and channel.
    """
    global _last_monitored_log

    current = (log_path, channel)
    if current != _last_monitored_log:
        logger.info(f"Monitoring new log file: {log_path} (Channel: {channel})")
        _last_monitored_log = current
        switch_log_file(log_path)
    else:
        logger.debug(f" Already monitoring the same log file: {log_path} (no switch)")

def switch_log_file(new_path: str):
    """
    Cleanly switch to a new log file for monitoring.
    """
    if not os.path.isfile(new_path):
        logger.error(f"Cannot switch to log file: '{new_path}' does not exist.")
        return

    stop_log_monitor()      # Stop current monitoring thread
    time.sleep(0.2)         # Small delay to ensure thread cleanup
    start_log_monitor(new_path)  # Start monitoring new log file

_last_monitored_log = None  # Global variable to track monitored log

def handle_log_line(line: str):
    # Ignore all log lines; do nothing or minimal processing
    pass

def start_log_monitor(new_path: str):
    import threading

    def monitor():
        with open(new_path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, os.SEEK_END)  # Start at end of file (tail)
            while monitoring:
                line = f.readline()
                if line:
                    # Do NOT print or log lines here!
                    handle_log_line(line.strip())
                else:
                    time.sleep(0.1)

    global monitoring, log_monitor_thread
    monitoring = True
    log_monitor_thread = threading.Thread(target=monitor, daemon=True)
    log_monitor_thread.start()

def stop_log_monitor():
    global monitoring
    monitoring = False
    time.sleep(0.2)  # Wait for thread to cleanly stop

def get_version_from_manifest(exe_path: str, channel: Optional[str] = None) -> Optional[str]:
    """
    Reads the build_manifest.id file to extract version info.
    Uses the provided channel if available to determine the environment.
    """
    manifest_path = os.path.join(os.path.dirname(os.path.dirname(exe_path)), 'build_manifest.id')
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                data = json.loads(content)
                branch = data.get("Data", {}).get("Branch", "")
                version = branch.split("-")[2] if branch and len(branch.split("-")) > 2 else "Unknown"
                requested_p4_change_num = data.get("Data", {}).get("RequestedP4ChangeNum", "")

                environment = channel.upper() if channel else "Unknown"
                return f"{version} [{requested_p4_change_num}] ({environment})"
        except Exception as e:
            logger.error(f"Error reading build_manifest.id: {e}")
    else:
        logger.warning(f"build_manifest.id not found at {manifest_path}")
    return None


def extract_game_version_from_log(log_path: str) -> Optional[str]:
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "BuildVersion" in line:
                    parts = line.strip().split("BuildVersion:")
                    if len(parts) == 2:
                        return parts[1].strip()
    except Exception as e:
        logger.warning(f"Could not read game version from log: {e}")
    return None


def find_starcitizen_exe() -> Optional[Tuple[str, Optional[str], Optional[str]]]:
    """
    Finds StarCitizen.exe and extracts path, version, and channel.
    """
    try:
        for proc in psutil.process_iter(['name', 'exe']):
            if proc.info['name'] and proc.info['name'].lower() == 'starcitizen.exe':
                exe_path = proc.info['exe']
                if not exe_path or not os.path.isfile(exe_path):
                    logger.warning("StarCitizen.exe process found but executable path invalid.")
                    continue

                channel = None
                path_parts = exe_path.replace('/', '\\').upper().split('\\')
                for folder_name in ['LIVE', 'PTU', 'PUBLIC_TEST', 'EVOCATI']:
                    if folder_name in path_parts:
                        channel = "PTU" if folder_name == "PUBLIC_TEST" else folder_name
                        break

                version = get_version_from_manifest(exe_path, channel)

                return exe_path, version, channel
    except Exception as e:
        logger.error(f"Error finding StarCitizen.exe process: {e}")
    return None

def monitor_log_file(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, 2)  # Seek to end of file for tailing
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                print(f"New log line: {line.strip()}")
    except Exception as e:
        logger.error(f"Error monitoring log file: {e}")

def monitor_version_updates(poll_interval=5):
    global game_version
    last_version = None

    while True:
        exe_info = find_starcitizen_exe()
        if exe_info:
            exe_path, version, channel = exe_info

            if not version:
                version = get_version_from_manifest(exe_path, channel)
            if not version:
                log_path = os.path.join(os.path.dirname(exe_path), channel.upper(), "Game.log")
                version = extract_game_version_from_log(log_path) or "Unknown Version"

            if version != last_version:
                print(f"Star Citizen Version: {version}")
                last_version = version
                game_version = version
        else:
            if last_version != "StarCitizen.exe not running":
                print("StarCitizen.exe is not running.")
                last_version = "StarCitizen.exe not running"
                game_version = last_version

        time.sleep(poll_interval)

def start_version_monitor():
    try:
        sc_info = find_starcitizen_exe()
        if not sc_info:
            logger.error("Could not detect Star Citizen process.")
            return

        exe_path, version, channel = sc_info

        if channel and os.path.isdir(os.path.dirname(os.path.dirname(exe_path))):
            base_dir = os.path.dirname(os.path.dirname(exe_path))
            log_path, channel = get_log()



        # Fallback if version wasn't already found
        if not version:
            version = get_version_from_manifest(exe_path, channel)
        if not version:
            version = extract_game_version_from_log(log_path)

        logger.info(f"Monitoring log file: {log_path}")
        logger.info(f"Star Citizen Version: {version or 'Unknown'} (Channel: {channel})")

        monitor_thread = threading.Thread(target=monitor_log_file, args=(log_path,), daemon=True)
        monitor_thread.start()
    except Exception as e:
        logger.error(f"Failed to start version monitor: {e}", exc_info=True)


# --- Resource Path Helper ---
def resource_path(filename):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, filename)
    return os.path.abspath(filename)


def parse_death_event(line):
    match = DEATH_REGEX.match(line)
    if match:
        data = match.groupdict()
        logging.debug(f"Raw parsed death event data: {data}")
        data["victim"] = ACTORS.get(data["victim"], data["victim"])
        data["killer"] = ACTORS.get(data["killer"], data["killer"])
        data["weapon"] = data.get("weapon", "Unknown")
        return data
    return None


def is_game_entity(name: str) -> bool:
    return any(keyword in name.lower() for keyword in [
        "loadingplatform", "elevator", "shuttle", "station", "turret", "ai_", "_", "zone"
    ])

def is_crash_death(data):
    damage_type = data['damage_type'].lower()
    killer = data['killer'].lower()
    zone = data['zone'].lower()

    # Crash detection logic
    return (
        damage_type == 'crash' or
        "collision" in damage_type or
        "impact" in damage_type or
        "planet" in zone or
        "moon" in zone or
        "atmosphere" in zone or
        "loadingplatform" in killer or
        "elevator" in killer or
        "hangar" in zone or
        "pad" in zone
    )


from actors import ACTORS  # Import the actors dictionary

def classify_death(data):
    """Classify death events with ACTORS integration and precise vehicle PvP distinction"""
    try:
        # Safely get and normalize all values with proper fallbacks
        damage_type = str(data.get('damage_type', 'N/A')).lower().strip()
        victim = str(ACTORS.get(data.get('victim', 'N/A'), data.get('victim', 'N/A'))).strip()
        killer = str(ACTORS.get(data.get('killer', 'N/A'), data.get('killer', 'N/A'))).strip()
        weapon = str(data.get('weapon', 'N/A')).lower().strip()
        zone = str(data.get('zone', 'N/A')).lower().strip()
        
        # Debug logging (only in dev mode)
        if "dev" in startup_flag:
            logging.debug(f"Classification inputs - Damage: {damage_type}, Victim: {victim}, Killer: {killer}, Weapon: {weapon}, Zone: {zone}")

        # Check for invalid data
        if 'N/A' in (damage_type, victim, killer):
            logging.debug("Invalid data - missing required fields")
            return "N/A"

        # Determine context flags
        is_vehicle_zone = any(x in zone for x in ['cutlass', 'drak_', 'ship_', 'vehicle_'])
        is_vehicle_weapon = any(x in weapon for x in ['vehicle', 'ship', 'turret', 'laser', 'repeater', 'cannon'])
        is_npc = lambda x: str(x).startswith(("PU_", "NPC_")) or "AI_" in str(x) or str(x) in ACTORS.get('npcs', [])

        # Define environmental terms
        env_terms = ['boundary', 'vacuum', 'debris', 'hazard', 'environment']
        env_killers = ('environment', 'unknown', 'n/a') + tuple(env_terms)

        killer_lower = killer.lower()
        zone_lower = zone.lower()
        damage_type_lower = damage_type.lower()

        # 1. Environmental Deaths (check first)
        if (killer_lower in env_killers or
            any(term in zone_lower for term in env_terms) or
            any(term in damage_type_lower for term in env_terms)):
            logging.debug("Classified as Environmental death")
            return "🌍 Environmental"

        # 2. PvE Kill detection
        if is_npc(victim):
            logging.debug("Classified as PvE Kill (NPC victim)")
            return "⚔️ PvE Kill"

        # 3. Vehicle-related deaths
        if is_vehicle_zone or is_vehicle_weapon:
            # PvP Vehicle Combat
            if victim != killer and killer_lower not in env_killers:
                if is_vehicle_weapon:
                    logging.debug("Classified as PvP Vehicle Kill (Weapons)")
                    return "⚔️ PvP Vehicle Kill (Weapons)"
                if damage_type_lower == 'vehicledestruction':
                    logging.debug("Classified as PvP Vehicle Kill (Destruction)")
                    return "⚔️ PvP Vehicle Kill (Destruction)"
                if damage_type_lower == 'crash':
                    logging.debug("Classified as PvP Vehicle Crash (Caused)")
                    return "💥 PvP Vehicle Crash (Caused)"

            # Environmental/Self Vehicle Crashes
            if damage_type_lower == 'crash':
                if victim == killer:
                    logging.debug("Classified as Vehicle Crash (Self)")
                    return "💥 Vehicle Crash (Self)"
                if killer_lower in env_killers:
                    logging.debug("Classified as Vehicle Crash (Environmental)")
                    return "💥 Vehicle Crash (Environmental)"
                logging.debug("Classified as generic Vehicle Crash")
                return "💥 Vehicle Crash"

        # 4. Suicide cases
        if victim == killer:
            if damage_type_lower in ('suicide', 'selfdestruct'):
                logging.debug("Classified as Suicide (explicit)")
                return "🧨 Suicide"
            if weapon in ('self', 'self-inflicted'):
                logging.debug("Classified as Suicide (weapon-based)")
                return "🧨 Suicide"
            if killer in ACTORS.get('environmental', []):
                logging.debug("Classified as Suicide (environmental actor)")
                return "🧨 Suicide"

        # 5. PvP Infantry Combat
        if weapon != 'n/a' and not is_npc(killer):
            if any(x in weapon for x in ['rifle', 'pistol', 'gun', 'bullet']):
                logging.debug("Classified as PvP Kill (infantry weapons)")
                return "⚔️ PvP Kill"

        # 6. NPC Killers
        if is_npc(killer):
            logging.debug("Classified as PvE Kill (NPC killer)")
            return "⚔️ PvE Kill"

        # 7. Final fallbacks
        if damage_type_lower == 'bullet':
            logging.debug("Classified as PvP Kill (bullet damage fallback)")
            return "⚔️ PvP Kill"
        if killer_lower not in env_killers and not is_npc(killer):
            logging.debug("Classified as PvP Kill (generic fallback)")
            return "⚔️ PvP Kill"

        logging.debug("No classification matched")
        return "N/A"

    except Exception as e:
        logging.error(f"Classification error: {str(e)}", exc_info=True)
        return "N/A"

def send_to_discord(data, kill_type, user_data=None):

    if is_offline_mode():
        logging.info(f"Offline mode enabled. Skipping Discord webhook for: {kill_type}")
        return
    try:
        webhook_url = DISCORD_WEBHOOK_URL

        # Updated color map with new crash type
        color_map = {
            "💥 Crash": 0x8e44ad,
            "💥 Vehicle Crash": 0x8e44ad,
            "💥 Vehicle Crash (Self)": 0x9932CC,  # Dark orchid color
            "🧨 Suicide": 0xe74c3c,
            "🌍 Environmental": 0x3498db,
            "🚀 Vehicle Destruction": 0x9b59b6,
            "⚔️ PvP Kill": 0xffaa00,
            "⚔️ PvP Kill (Vehicle)": 0xff8000,
        }

        # Updated skip API types
        skip_api_types = ["🧨 Suicide", "🌍 Environmental", "💥 Crash", "💥 Vehicle Crash", "💥 Vehicle Crash (Self)"]
        is_simple_event = kill_type in skip_api_types

        # Get names from parsed data
        victim_name = data["victim"]
        killer_name = data["killer"]
        weapon = data["weapon"]

        # Initialize additional fields
        victim_organization = "N/A"
        victim_url = "N/A"
        killer_organization = "N/A"
        killer_url = "N/A"

        if is_simple_event:
            # Handle new crash types
            if kill_type in ["💥 Vehicle Crash", "💥 Vehicle Crash (Self)"]:
                killer_name = "Vehicle System" if kill_type == "💥 Vehicle Crash (Self)" else "Environment"
                weapon = "Vehicle Collision"
                title = "🚗 Vehicle Crash" if "Self" in kill_type else "🚗 Vehicle Accident"
            elif kill_type == "🧨 Suicide":
                killer_name = "Self"
                weapon = "Self-inflicted"
                title = "🧨 Suicide Event"
            elif kill_type == "💥 Crash":
                killer_name = "Environment"
                weapon = "Collision"
                title = "💥 Crash Event"
            elif kill_type == "🌍 Environmental":
                killer_name = "Environment"
                title = "🌍 Environmental Hazard"
        else:
            # Existing API lookup logic for combat events
            victim_user = client.get_user(data['victim'])
            killer_user = client.get_user(data['killer'])

            if victim_user and getattr(victim_user, "success", 0) == 1:
                victim_profile = getattr(victim_user.data, "profile", None)
                victim_org = getattr(victim_user.data, "organization", None)
                victim_name = getattr(victim_profile, "display", victim_name)
                victim_organization = getattr(victim_org, "name", "N/A")
                victim_url = getattr(getattr(victim_profile, "page", {}), "url", "N/A")

            if killer_user and getattr(killer_user, "success", 0) == 1:
                killer_profile = getattr(killer_user.data, "profile", None)
                killer_org = getattr(killer_user.data, "organization", None)
                killer_name = getattr(killer_profile, "display", killer_name)
                killer_organization = getattr(killer_org, "name", "N/A")
                killer_url = getattr(getattr(killer_profile, "page", {}), "url", "N/A")

            title = f"{kill_type} Event Detected"
            if "Vehicle" in kill_type:
                title = f"🚀 Vehicle Combat: {'PvP' if 'PvP' in kill_type else 'Environmental'}"
                weapon = f"{weapon} (Vehicle Destruction)" if weapon != "Unknown" else "Vehicle Destruction"

        # Build embed fields
        fields = [
            {
                "name": "📍 Info",
                "value": f"🕒 **Time**: {data['timestamp']} - {data.get('discord_timestamp', 'No Discord timestamp available')}\n🌌 **Zone**: {data['zone']}",
                "inline": False
            },
            {
                "name": "⚔️ Combatants",
                "value": f"🧍 **Victim**: {victim_name} *(ID: {data['victim_id']})*\n" +
                         (f"🗡️ **Killer**: {killer_name} *(ID: {data['killer_id']})*" 
                          if not kill_type.endswith("(Self)") else ""),
                "inline": False
            },
            {
                "name": "💥 Details",
                "value": f"🔫 **Weapon**: {weapon}\n☠️ **Damage Type**: {data['damage_type']}",
                "inline": False
            }
        ]

        if not is_simple_event:
            fields.extend([
                {
                    "name": "🏳️ Organizations",
                    "value": f"👤 **Victim Org**: {victim_organization}\n⚔️ **Killer Org**: {killer_organization}",
                    "inline": False
                },
                {
                    "name": "📄 RSI Profiles",
                    "value": f"[Victim Profile]({victim_url})\n[Killer Profile]({killer_url})",
                    "inline": False
                }
            ])

        if user_data:
            fields.append({
                "name": "👤 Reporter Info",
                "value": (
                    f"👥 **Username**: {user_data.get('Username', 'Unknown')}\n"
                    f"🆔 **SCKillTrac ID**: {user_data.get('SCKillTrac ID', 'N/A')}\n"
                    f"🔗 **UUID**: {user_data.get('UUID', 'N/A')}"
                ),
                "inline": False
            })


        embed = {
            "title": title,
            "color": color_map.get(kill_type, 0xAAAAAA),
            "fields": fields,
            "thumbnail": {"url": LOGO_URL},
            "footer": {"text": f"Star Citizen Kill Tracker System [Version info : {VERSION}-{BUILD_TYPE}({DEPLOYMENT_SCOPE})]"}
        }

        payload = json.dumps({"embeds": [embed]})
        response = requests.post(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code != 204:
            logging.error(f"Discord webhook failed: {response.status_code} - {response.text}")
        else:
            logging.info(f"{kill_type} event sent to Discord successfully.")

    except Exception as e:
        logging.error(f"Error sending kill report to Discord: {e}")

        # Build the embed fields
        fields = [
            {
                "name": "📍 Info",
                "value": (
                    f"🕒 **Time**: {data['timestamp']} - {data.get('discord_timestamp', 'No Discord timestamp available')}\n\n"
                    f"🌌 **Zone**: {data['zone']}"
                ),
                "inline": False
            },
            {
                "name": "⚔️ Combatants",
                "value": (
                    f"🧍 **Player**: {victim_name} *(ID: {data['victim_id']})*" if is_simple_event else
                    f"🧍 **Victim**: {victim_name} *(ID: {data['victim_id']})*\n"
                    f"🗡️ **Killer**: {killer_name} *(ID: {data['killer_id']})*"
                ),
                "inline": False
            },
            {
                "name": "💥 Details",
                "value": (
                    f"💀 **Method**: {weapon}" if is_simple_event else
                    f"🔫 **Weapon**: {weapon}\n☠️ **Damage Type**: {data['damage_type']}"
                ),
                "inline": False
            }
        ]

        # Only add orgs and profiles for non-simple events
        if not is_simple_event:
            fields.extend([
                {
                    "name": "🏳️ Organizations",
                    "value": (
                        f"👤 **Victim Org**: {victim_organization}\n"
                        f"⚔️ **Killer Org**: {killer_organization}"
                    ),
                    "inline": False
                },
                {
                    "name": "📄 RSI Profiles",
                    "value": (
                        f"[Victim Profile]({victim_url})\n"
                        f"[Killer Profile]({killer_url})"
                    ),
                    "inline": False
                }
            ])
            if user_data:
                fields.append({
                    "name": "👤 Reporter Info",
                    "value": (
                        f"👥 **Username**: {user_data.get('Username', 'Unknown')}\n"
                        f"🆔 **SCKillTrac ID**: {user_data.get('SCKillTrac ID', 'N/A')}\n"
                        f"🔗 **UUID**: {user_data.get('UUID', 'N/A')}"
                    ),
                    "inline": False
                })


        embed = {
            "title": title,
            "color": color_map.get(kill_type, 0xAAAAAA),
            "fields": fields,
            "thumbnail": {"url": LOGO_URL},
            "footer": {"text": f"Star Citizen Kill Tracker System [Version info : {VERSION}-{BUILD_TYPE}({DEPLOYMENT_SCOPE})]"}
        }

        payload = json.dumps({"embeds": [embed]})
        response = requests.post(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code != 204:
            logging.error(f"Discord webhook failed: {response.status_code} - {response.text}")
        else:
            logging.info(f"{kill_type} event sent to Discord successfully.")

    except Exception as e:
        logging.error(f"Error sending kill report to Discord: {e}")

def send_pve_to_discord(data, kill_type, user_data=None):
    if is_offline_mode():
        logging.info(f"Offline mode enabled. Skipping Discord webhook for: {kill_type}")
        return

    try:
        webhook_url = PVE_WEBHOOK_URL

        color_map = {
            "⚔️ PvE Kill": 0xffaa00,
        }

        fields = [
            {
                "name": "📍 Info",
                "value": f"🕒 **Time**: {data['timestamp']} - {data.get('discord_timestamp', 'No Discord timestamp available')}\n🌌 Zone: {data['zone']}",
                "inline": False
            },
            {
                "name": "⚔️ Combatants",
                "value": f"🧍 Victim: {data['victim']}\n🗡️ Killer: {data['killer']}",
                "inline": False
            },
            {
                "name": "💥 Combat Details",
                "value": f"🔫 Weapon: {data['weapon']}\n☠️ Method: {data['damage_type']}",
                "inline": False
            }
        ]

        if user_data:
            fields.append({
                "name": "👤 Reporter Info",
                "value": (
                    f"👥 **Username**: {user_data.get('Username', 'Unknown')}\n"
                    f"🆔 **SCKillTrac ID**: {user_data.get('SCKillTrac ID', 'N/A')}\n"
                    f"🔗 **UUID**: {user_data.get('UUID', 'N/A')}"
                ),
                "inline": False
            })

        embed = {
            "title": f"{kill_type} Detected",
            "color": color_map.get(kill_type, 0xAAAAAA),
            "fields": fields,
            "thumbnail": {"url": LOGO_URL},
            "footer": {
                "text": f"Star Citizen Kill Tracker System - PVE [Version info : {VERSION}-{BUILD_TYPE}({DEPLOYMENT_SCOPE})]"
            }
        }

        payload_json = json.dumps({"embeds": [embed]})
        response = requests.post(
            webhook_url,
            data=payload_json,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code != 204:
            logging.error(f"Discord webhook failed: {response.status_code} - {response.text}")
        else:
            logging.info(f"{kill_type} event sent to Discord successfully.")

    except Exception as e:
        logging.error(f"Error sending kill report to Discord: {e}")

def send_death_log_to_discord(data, user_data=None):
    if is_offline_mode():
        logging.info(f"Offline mode enabled. Skipping Discord webhook for: {data}")
        return
    try:
        webhook_url = DEATH_REGEX_WEBHOOK_URL

        # Build plain one-liner text
        content = (
            f"[{data['timestamp']}] {data['victim']} (ID: {data['victim_id']}) "
            f"was killed by {data['killer']} (ID: {data['killer_id']}) in {data['zone']} "
            f"using {data['weapon']} ({data['damage_type']})"
        )

        if data.get("class"):
            content += f" | Class: {data['class']}"

        payload = {
            "content": content
        }

        response = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code != 204:
            logging.error(f"Death log webhook failed: {response.status_code} - {response.text}")
        else:
            logging.info("Sent one-line death log to Discord.")

        # --- Optional reporter info embed ---
        if user_data:
            reporter_embed = {
                "title": "👤 Reporter Info",
                "color": 0x3498db,
                "fields": [
                    {
                        "name": "🧑 Reporter Details",
                        "value": (
                            f"👥 **Username**: {user_data.get('Username', 'Unknown')}\n"
                            f"🆔 **SCKillTrac ID**: {user_data.get('SCKillTrac ID', 'N/A')}\n"
                            f"🔗 **UUID**: {user_data.get('UUID', 'N/A')}"
                        ),
                        "inline": False
                    }
                ],
                "footer": {
                    "text": f"Submitted via Kill Tracker System [Version: {VERSION}-{BUILD_TYPE}({DEPLOYMENT_SCOPE})]"
                },
                "thumbnail": {
                    "url": LOGO_URL
                }
            }

            reporter_payload = {
                "embeds": [reporter_embed]
            }

            reporter_response = requests.post(
                webhook_url,
                json=reporter_payload,
                headers={"Content-Type": "application/json"}
            )

            if reporter_response.status_code != 204:
                logging.error(f"Reporter info webhook failed: {reporter_response.status_code} - {reporter_response.text}")
            else:
                logging.info("Sent reporter info embed to Discord.")

    except Exception as e:
        logging.error(f"Error sending death log to Discord: {e}")

def handle_death_event(line):
    # Step 1: Parse the death event data from the line
    data = parse_death_event(line)
    if data:
        logging.info(f"Death event detected: {data}")

        # Step 2: Classify the death type
        kill_type = classify_death(data)
        if kill_type:
            logging.info(f"Kill type: {kill_type}")

            # Step 3: Send the event to Discord
            send_to_discord(data, kill_type)
        else:
            logging.info("Kill type is None, skipping Discord send.")
    else:
        logging.error("Failed to parse death event.")

def add_discord_timestamp(data, timestamp_key="timestamp"):
    raw_ts = data.get(timestamp_key)
    if raw_ts:
        try:
            dt = datetime.strptime(raw_ts, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            dt = datetime.strptime(raw_ts, "%Y-%m-%dT%H:%M:%SZ")
        
        discord_ts = f"<t:{int(dt.timestamp())}:F>"
        data['discord_timestamp'] = discord_ts
    else:
        logging.error(f"No timestamp found for {timestamp_key} in data")

# Load the encryption key and user data globally before monitor starts
key2 = load_encryption_key()
user_data = load_first_user_data(key2)

def monitor_log(death_overlay=None):
    global running, kill_tracking, user_data
    last_log_path = None
    log_file = None
    first_start = True

    while running:
        try:
            # --- Only process if StarCitizen.exe is running ---
            if not find_starcitizen_exe():
                time.sleep(1)
                continue

            # Always check which log we should be using (handles LIVE/PTU swap)
            log_path, log_channel = get_log()
            log_path = Path(log_path)

            # If the log file has changed (user swapped LIVE/PTU), reopen it
            if last_log_path != log_path:
                if log_file:
                    log_file.close()
                last_log_path = log_path
                logging.info(f"Monitoring log file: {log_path} (Channel: {log_channel})")

                # Wait for the new log file to exist
                while not log_path.exists() and running:
                    logging.info("Log file not found yet, retrying...")
                    time.sleep(1)

                if not log_path.exists():
                    logging.error("Log file not found. Exiting monitor.")
                    return

                log_file = log_path.open("r", encoding="utf-8", errors="replace")
                if first_start:
                    log_file.seek(0, 2)  # Go to end on first start
                    first_start = False
                else:
                    log_file.seek(0)     # On new log, read from top

            # Read new lines from the current log file
            with lock:
                if not kill_tracking:
                    time.sleep(0.1)
                    continue

            line = log_file.readline()

            if not line or not line.strip():
                time.sleep(0.1)
                continue

            # Filter for only death events
            if "Death" not in line:
                continue

            # Step 1: Parse the death event data
            data = parse_death_event(line)
            if not data:
                logging.error("Failed to parse death event.")
                continue

            logging.info(f"Death event detected: {data}")

            # Step 2: Classify the death type
            kill_type = classify_death(data)
            if not kill_type:
                logging.info("Kill type is None, skipping overlay/Discord send.")
                continue

            # Step 3: Show in overlay if enabled (with kill_type)
            if death_overlay:
                try:
                    death_overlay.show_death_log({
                        'timestamp': data.get('timestamp', ''),
                        'victim': data.get('victim', 'Unknown'),
                        'victim_id': data.get('victim_id', ''),
                        'killer': data.get('killer', 'Unknown'),
                        'killer_id': data.get('killer_id', ''),
                        'zone': data.get('zone', 'Unknown Location'),
                        'weapon': data.get('weapon', 'Unknown'),
                        'damage_type': data.get('damage_type', ''),
                        'class': data.get('class', ''),
                    }, kill_type)
                except Exception as e:
                    logging.error(f"Error showing death overlay: {e}")

            # Step 4: Add Discord timestamp
                except Exception as e:
                    logging.error(f"Error showing death overlay: {e}")

            # Step 4: Add Discord timestamp
            add_discord_timestamp(data)
            logging.info(f"Formatted Discord timestamp: {data['discord_timestamp']}")

            send_death_log_to_discord(data, user_data=user_data)
            logging.info(f"Kill type: {kill_type}")

            if kill_type == "⚔️ PvP Kill":
                send_to_discord(data, kill_type, user_data=user_data)
            elif kill_type == "⚔️ PvE Kill":
                send_pve_to_discord(data, kill_type, user_data=user_data)
            else:
                send_to_discord(data, kill_type, user_data=user_data)

        except Exception as e:
            logging.error(f"Monitor error: {str(e)}")
            traceback.print_exc()
            time.sleep(1)

            if log_file:
                try:
                    log_file.close()
                except Exception:
                    pass
                log_file = None

def create_image():
    try:
        response = requests.get(LOGO_URL)
        response.raise_for_status()
        img = Image.open(BytesIO(response.content)).resize((64, 64), Image.Resampling.LANCZOS)
        return img
    except Exception as e:
        logging.error(f"Tray icon fallback used: {e}")
        return Image.new("RGB", (64, 64), color=(255, 255, 255))

def cleanup_resources(discord_rpc=None, open_files=None, threads=None):
    """
    Comprehensive resource cleanup for Star Citizen Kill Tracker
    Handles Discord RPC, files, processes, threads, and temp files
    """
    import os
    import psutil
    import logging
    import threading
    from typing import List, Optional
    
    # Setup basic logging if not configured
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    # Initialize default mutable parameters
    open_files = open_files or []
    threads = threads or []
    
    # 1. Discord RPC Cleanup
    if discord_rpc:
        try:
            discord_rpc.close()
            logging.info("Discord RPC disconnected")
        except Exception as e:
            logging.warning(f"Discord RPC disconnect failed: {str(e)}")

    # 2. File Handle Cleanup
    for file in open_files:
        try:
            if not file.closed:
                file.close()
        except Exception as e:
            logging.warning(f"Failed closing file: {str(e)}")

    # 3. Thread Termination
    for thread in threads:
        try:
            if thread.is_alive():
                # Try standard thread stopping methods
                if hasattr(thread, 'stop'):
                    thread.stop()
                elif hasattr(thread, '_Thread__stop'):
                    thread._Thread__stop()
                
                # Wait for thread to finish
                thread.join(timeout=1.0)
                if thread.is_alive():
                    logging.warning(f"Thread {thread.name} didn't stop gracefully")
        except Exception as e:
            logging.error(f"Thread stop failed: {str(e)}")

    # 4. Child Process Termination
    try:
        current_process = psutil.Process(os.getpid())
        for child in current_process.children(recursive=True):
            try:
                if child.is_running():
                    child.terminate()
                    logging.info(f"Terminated child process: {child.pid}")
            except psutil.NoSuchProcess:
                pass
    except Exception as e:
        logging.error(f"Process cleanup failed: {str(e)}")


from sc_feedback import create_feedback_dialog

def restart_application():
    """Restart the SC Kill Tracker application"""
    try:
        print("Restarting SC Kill Tracker...")

        # Get the current script path and arguments
        script_path = os.path.abspath(sys.argv[0])
        args = sys.argv[1:]

        # Restore console output before restarting
        restore_console_output()

        # Close any open windows/resources gracefully
        try:
            # If there's a main window, try to close it
            if 'root' in globals():
                root.quit()
                root.destroy()
        except:
            pass

        # Start new instance
        if os.name == 'nt':  # Windows
            # Use subprocess to start new instance
            subprocess.Popen([sys.executable, script_path] + args,
                           creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:  # Other OS
            subprocess.Popen([sys.executable, script_path] + args)

        # Exit current instance
        sys.exit(0)

    except Exception as e:
        print(f"Error restarting application: {e}")
        logging.error(f"Failed to restart application: {e}")
        # Show error message if restart fails
        try:
            show_message("Restart Error", f"Failed to restart application: {e}", "error")
        except:
            pass

def show_about(root):
    import tkinter as tk
    from PIL import Image, ImageTk
    import os
    import requests
    from io import BytesIO

    win = tk.Toplevel(root)
    win.title("Star Citizen Kill Tracker - About")
    win.configure(bg="#1a252f")
    win.resizable(True, True)

    # Calculate scale factor for dynamic UI scaling using improved scaling
    scale = get_scale_factor()
    # Ensure minimum scale for readability
    scale = max(scale, 1.0)

    # Dynamically size the window
    base_width, base_height = 500, 500
    win.geometry(f"{int(base_width * scale)}x{int(base_height * scale)}")

    try:
        logo_path = get_local_logo_path()
        if not logo_path or not os.path.exists(logo_path):
            raise FileNotFoundError("Logo file does not exist")

        # Set window icon
        icon_img = Image.open(logo_path).convert("RGBA")
        icon_img.thumbnail((int(64 * scale), int(64 * scale)), Image.LANCZOS)
        icon_tk = ImageTk.PhotoImage(icon_img)
        win.iconphoto(True, icon_tk)

        # Display main logo
        pil_logo = Image.open(logo_path).convert("RGBA")
        pil_logo.thumbnail((int(400 * scale), int(250 * scale)), Image.LANCZOS)
        logo_display = ImageTk.PhotoImage(pil_logo)

        logo_label = tk.Label(win, image=logo_display, bg="#1a252f")
        logo_label.image = logo_display
        logo_label.pack(pady=(int(20 * scale), int(10 * scale)))

        # Load HTG icon
        htg_response = requests.get("https://raw.githubusercontent.com/HarleyTG-O/htg-logo/main/HTG.png")
        htg_img_data = BytesIO(htg_response.content)
        small_htg = Image.open(htg_img_data).convert("RGBA")
        small_htg.thumbnail((int(16 * scale), int(16 * scale)))
        htg_icon = ImageTk.PhotoImage(small_htg)

        font_base = int(12 * scale)

        # Version info
        tk.Label(
            win,
            text=f"SC Kill Tracker [Version info : {VERSION}-{BUILD_TYPE}({DEPLOYMENT_SCOPE})]",
            justify="left",
            font=("Segoe UI", font_base),
            fg="white",
            bg="#1a252f"
        ).pack(pady=(0, int(5 * scale)))

        studio_frame = tk.Frame(win, bg="#1a252f")
        studio_frame.pack(pady=(0, int(10 * scale)))

        tk.Label(studio_frame, text="Developed by", font=("Segoe UI", font_base), fg="white", bg="#1a252f").pack(side="left", padx=(0, int(4 * scale)))

        htg_icon_label = tk.Label(studio_frame, image=htg_icon, bg="#1a252f")
        htg_icon_label.image = htg_icon
        htg_icon_label.pack(side="left", padx=(0, int(4 * scale)))

        tk.Label(studio_frame, text="Harley's Studios", font=("Segoe UI", font_base), fg="white", bg="#1a252f").pack(side="left")

    except Exception as e:
        logging.error(f"Error loading logo or HTG icon: {e}")
        tk.Label(win, text="Error: Failed to load images.", font=("Segoe UI", font_base), fg="red", bg="#1a252f").pack(pady=int(20 * scale))

    # About Text
    tk.Label(
        win,
        text="A simple tool for tracking player kills in Star Citizen.\nThis tool is not affiliated with Cloud Imperium Games.",
        justify="left",
        font=("Segoe UI", font_base),
        fg="white",
        bg="#1a252f",
        padx=int(8 * scale),
        pady=int(10 * scale)
    ).pack(pady=(0, int(5 * scale)))

    # Feedback button
    feedback_btn = tk.Button(
        win,
        text="Send Feedback",
        font=("Segoe UI", int(11 * scale)),
        bg="#2c5a7c",
        fg="white",
        activebackground="#3b7eaf",
        activeforeground="white",
        padx=int(10 * scale),
        pady=int(5 * scale),
        relief=tk.FLAT,
        command=lambda: create_feedback_dialog(root)
    )
    feedback_btn.pack(pady=int(15 * scale))

    # Center the window
    win.update_idletasks()
    width, height = win.winfo_width(), win.winfo_height()
    x = (win.winfo_screenwidth() - width) // 2
    y = (win.winfo_screenheight() - height) // 2
    win.geometry(f"{width}x{height}+{x}+{y}")

tray_icon_initialized = False

def tray_icon(root):
    global tray_icon_initialized, ENABLE_DISCORD_RPC, RPC
    if tray_icon_initialized:
        return  # Already initialized

    tray_icon_initialized = True  # Mark as initialized

    def on_show_about(icon, item):
        root.after(0, lambda: show_about(root))

    def on_open_feedback(icon, item):
        root.after(0, lambda: create_feedback_dialog(root))

    def on_force_quit(icon, item):
        """Force quit the application with confirmation"""
        confirm = show_message(
            "Force Quit",
            "Are you sure you want to force quit? Unsaved data may be lost.",
            "question"
        )
        if confirm:
            global running
            running = False
            
            # Immediate cleanup
            cleanup_resources()
            
            if icon:
                icon.stop()
            
            # Quick exit sequence
            root.after(100, lambda: [root.quit(), os._exit(0)])


    def on_open_main_menu(icon, item):
        """Show the main menu window"""
        root.after(0, lambda: show_main_menu(root))

    def build_menu(icon=None):
        return pystray.Menu(
            pystray.MenuItem(f"[Version info : {VERSION}-{BUILD_TYPE}({DEPLOYMENT_SCOPE})]", lambda icon, item: None, enabled=False),
            pystray.MenuItem("Main Menu", on_open_main_menu),
            pystray.MenuItem("Force Quit", on_force_quit),
        )

    icon = pystray.Icon(
        "SC KillTracker",
        icon=create_image(),
        title="SC Kill Tracker",
        menu=build_menu()
    )

    threading.Thread(target=icon.run, daemon=True).start()

# Function to load and show the game.log content in Debug Tab
def load_game_log_into_debug(log_text_widget):
    """Reads the game.log and outputs it to the Debug tab."""
    log_path, log_channel = get_log()  # Unpack tuple (path, channel)
    try:
        if os.path.exists(log_path):
            with open(log_path, "r", encoding='utf-8') as file:
                log_content = file.read()
                log_text_widget.config(state=tk.NORMAL)
                log_text_widget.delete(1.0, tk.END)
                log_text_widget.insert(tk.END, f"----- Game Log ({log_channel}) -----\n")
                log_text_widget.insert(tk.END, log_content)
                log_text_widget.config(state=tk.DISABLED)
                log_text_widget.see(tk.END)  # Auto-scroll to bottom
        else:
            log_text_widget.config(state=tk.NORMAL)
            log_text_widget.delete(1.0, tk.END)
            log_text_widget.insert(tk.END, f"No game.log found at:\n{log_path}")
            log_text_widget.config(state=tk.DISABLED)
    except Exception as e:
        log_text_widget.config(state=tk.NORMAL)
        log_text_widget.delete(1.0, tk.END)
        log_text_widget.insert(tk.END, f"Error reading game.log: {e}")
        log_text_widget.config(state=tk.DISABLED)

def load_settings(
    debug_text_color: tk.StringVar,
    auto_refresh: Optional[tk.BooleanVar] = None,
    refresh_interval: Optional[tk.IntVar] = None
) -> None:
    """
    Load settings from JSON file into Tkinter variables.
    Note: Offline mode is no longer loaded from settings as it's now temporary.
    
    Args:
        debug_text_color: StringVar for debug text color
        auto_refresh: Optional BooleanVar for auto-refresh setting
        refresh_interval: Optional IntVar for refresh interval
    """
    default_settings = {
        "debug_text_color": "lime",
        "auto_refresh": True,
        "refresh_interval": 1
    }

    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as f:
                settings = json.load(f)
        else:
            settings = default_settings
            with open(SETTINGS_FILE, "w") as f:
                json.dump(default_settings, f, indent=4)

        # Apply settings to variables (excluding offline_mode)
        debug_text_color.set(settings.get("debug_text_color", default_settings["debug_text_color"]))
        
        if auto_refresh is not None:
            auto_refresh.set(settings.get("auto_refresh", default_settings["auto_refresh"]))
        if refresh_interval is not None:
            refresh_interval.set(settings.get("refresh_interval", default_settings["refresh_interval"]))

    except (json.JSONDecodeError, PermissionError) as e:
        print(f"Error loading settings: {e}. Using default values.")
        debug_text_color.set(default_settings["debug_text_color"])
        if auto_refresh is not None:
            auto_refresh.set(default_settings["auto_refresh"])
        if refresh_interval is not None:
            refresh_interval.set(default_settings["refresh_interval"])


def save_settings(
    debug_text_color: tk.StringVar,
    auto_refresh: Optional[tk.BooleanVar] = None,
    refresh_interval: Optional[tk.IntVar] = None
) -> None:
    """
    Save current settings to JSON file.
    Note: Offline mode is no longer saved as it's now temporary.
    
    Args:
        debug_text_color: StringVar for debug text color
        auto_refresh: Optional BooleanVar for auto-refresh setting
        refresh_interval: Optional IntVar for refresh interval
    """
    settings = {
        "debug_text_color": debug_text_color.get()
    }

    if auto_refresh is not None:
        settings["auto_refresh"] = auto_refresh.get()
    if refresh_interval is not None:
        settings["refresh_interval"] = refresh_interval.get()

    try:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=4)
    except (PermissionError, TypeError) as e:
        print(f"Error saving settings: {e}")

debug_output = None
import platform


def game_version() -> Optional[str]:
    """
    Attempts to determine the Star Citizen game version from either the running process
    or the resolved Game.log file path.
    
    Returns:
        A formatted version string or None if it cannot be determined.
    """
    try:
        sc_info = find_starcitizen_exe()
        if sc_info:
            exe_path, version, _ = sc_info
            if version:
                return version

        # Fallback to reading from Game.log
        log_path, _ = get_log()
        return extract_game_version_from_log(log_path)
    except Exception as e:
        logger.error(f"Unable to determine game version: {e}")
        return None


game_version = game_version()
if game_version:
    print(f"Detected Star Citizen version: {game_version}")
else:
    print("Could not detect Star Citizen version.")

if startup_flag == "guest":
    key = load_encryption_key()
    user_data = {
        "Username": "Guest",
        "SCKillTrac ID": "Guest@SCKillTrac",
        "UUID": f"Guest-SCKillTrac-{uuid.uuid4()}"
    }
    globals()["user_data"] = user_data

def add_user_info_section(parent_frame):
    """Add a professional user info section to the main menu tab with resolution scaling and font object support."""
    try:
        global user_data, startup_flag

        # --- Dynamic scale factor based on screen resolution ---
        scale = get_scale_factor()
        # Increase scale by 50% overall for bigger fonts and spacing in user info
        scale *= 1.5
        # Ensure minimum scale for readability
        scale = max(scale, 1.2)

        root = parent_frame.winfo_toplevel()
        fonts = getattr(root, "custom_fonts", {})

        if user_data is None:
            key = load_encryption_key()
            user_data = load_first_user_data(key)

        if user_data:
            user_info_frame = tk.Frame(parent_frame, bg="#22303c")
            user_info_frame.pack(pady=(int(10 * scale), int(10 * scale)), padx=int(10 * scale), fill="x")

            # Use root.custom_fonts if available, else fallback
            font_main = fonts.get("label", ("Segoe UI", int(13 * scale), "bold"))
            font_id = ("Segoe UI", int(11 * scale))
            font_uuid = ("Segoe UI", int(9 * scale), "italic")
            font_status = ("Segoe UI", int(10 * scale), "italic")

            # Welcome message
            tk.Label(
                user_info_frame,
                text=f"👋 Welcome, {user_data.get('Username', 'Pilot')}!",
                font=font_main,
                fg="#00bfff",
                bg="#22303c",
                anchor="w"
            ).pack(anchor="w", padx=int(10 * scale), pady=(0, int(2 * scale)))

            # SCKillTrac ID
            tk.Label(
                user_info_frame,
                text=f"🆔 SCKillTrac ID: {user_data.get('SCKillTrac ID', 'N/A')}",
                font=font_id,
                fg="white",
                bg="#22303c",
                anchor="w"
            ).pack(anchor="w", padx=int(10 * scale))

            # UUID (small, gray)
            tk.Label(
                user_info_frame,
                text=f"🔗 UUID: {user_data.get('UUID', 'N/A')}",
                font=font_uuid,
                fg="#b0b0b0",
                bg="#22303c",
                anchor="w"
            ).pack(anchor="w", padx=int(10 * scale), pady=(0, int(6 * scale)))

            # Status message
            if startup_flag == "guest" or user_data.get("Username") == "Guest":
                status_msg = "Status: Guest Mode - Limited features."
            else:
                status_msg = "Status: Ready to track your Star Citizen adventures!"

            tk.Label(
                user_info_frame,
                text=status_msg,
                font=font_status,
                fg="#00bfff",
                bg="#22303c",
                anchor="w"
            ).pack(anchor="w", padx=int(10 * scale), pady=(0, int(4 * scale)))

        else:
            # Make default welcome font bigger
            default_font = fonts.get("label", ("Segoe UI", int(16 * scale), "italic"))
            tk.Label(
                parent_frame,
                text="👋 Welcome to SC Kill Tracker!\nPlease register or log in to personalize your experience.",
                font=default_font,
                fg="#00bfff",
                bg="#22303c",
                anchor="w",
                justify="left"
            ).pack(pady=(int(10 * scale), int(10 * scale)), padx=int(10 * scale), anchor="w")

    except Exception as e:
        logging.error(f"Error loading user data for main menu: {e}")


def on_main_menu_resize(event, root):
    # Don't scale content based on window resize - keep original scale factor
    scale = get_scale_factor()

    # Only update if widgets exist and window is not being destroyed
    try:
        if hasattr(root, 'custom_font_widgets') and root.winfo_exists():
            # Keep original font sizes - don't scale based on window size
            for widget_info in root.custom_font_widgets:
                widget = widget_info['widget']
                base_size = widget_info['base_size']
                weight = widget_info.get('weight', 'normal')

                if widget.winfo_exists():
                    # Use original scale factor only, not window-based scaling
                    new_size = max(8, int(base_size * scale))
                    new_font = ("Segoe UI", new_size, weight)
                    widget.configure(font=new_font)
    except Exception as e:
        logging.warning(f"Error updating fonts during resize: {e}")

    # Keep logo at original size - don't scale based on window size
    if hasattr(root, "logo_img_original") and hasattr(root, "logo_label"):
        try:
            if root.logo_label.winfo_exists():
                resized = root.logo_img_original.copy()
                # Use original scale factor only
                resized.thumbnail((int(180 * scale), int(90 * scale)), Image.LANCZOS)
                logo_img_displayed = ImageTk.PhotoImage(resized)
                root.logo_label.configure(image=logo_img_displayed)
                root.logo_label.image = logo_img_displayed
        except Exception as e:
            logging.warning(f"Error updating logo during resize: {e}")

class ColorManager:
    """Manages color schemes and conversions for the application"""

    def __init__(self):
        self.color_map = {
            "black": "#000000",  # Note: not available in dark mode
            "red": "#FF0000",
            "green": "#00FF00",
            "yellow": "#FFFF00",
            "blue": "#0000FF",
            "magenta": "#FF00FF",
            "cyan": "#00FFFF",
            "white": "#FFFFFF",
            "bright_black": "#808080",
            "bright_red": "#FF8080",
            "bright_green": "#80FF80",
            "bright_yellow": "#FFFF80",
            "bright_blue": "#8080FF",
            "bright_magenta": "#FF80FF",
            "bright_cyan": "#80FFFF",
            "bright_white": "#FFFFFF",
            # Additional optimized colors for dark themes
            "lime": "#00FF00",
            "orange": "#FFA500",
            "purple": "#800080",
            "pink": "#FFC0CB",
            "gray": "#808080",
            "dark_gray": "#404040"
        }

    def get_text_color(self, color_name: str) -> str:
        """Get hex color code for a given color name"""
        return self.color_map.get(color_name, color_name)

    def get_color_options(self) -> list:
        """Get list of available color options"""
        return [
            "lime", "white", "yellow", "cyan", "red", "orange", "green",
            "blue", "magenta", "purple", "pink", "bright_green",
            "bright_yellow", "bright_cyan", "bright_red", "bright_blue",
            "bright_magenta", "gray"
        ]


def show_main_menu(root):
    # Use the improved global scale factor function
    SCALE_FACTOR = get_scale_factor()
    
    # Helper function for scaled fonts with better high-DPI support
    def get_scaled_font(size, weight="normal"):
        scaled_size = int(size * SCALE_FACTOR)
        # Better minimum font sizes for high-DPI displays
        if SCALE_FACTOR >= 2.0:  # 4K+ displays
            min_size = 12
        elif SCALE_FACTOR >= 1.5:  # 1440p+ displays
            min_size = 10
        else:  # 1080p and below
            min_size = 8
        scaled_size = max(min_size, scaled_size)
        return ("Segoe UI", scaled_size, weight)
    
    # Helper function for scaled dimensions
    def scale_dim(value):
        return max(1, int(value * SCALE_FACTOR))
    
    # Load user language preference
    load_user_language()

    # Create menu window FIRST so it can be used as master
    menu_win = tk.Toplevel(root)
    menu_win.title(f"{get_text('app_title')} - {get_text('main_menu')}")
    menu_win.configure(bg="#1a252f")

    # Set as main window reference for dialog parenting
    set_main_window_ref(menu_win)

    # Make window stay on top with proper focus management
    menu_win.attributes('-topmost', True)
    menu_win.lift()
    menu_win.focus_force()

    # Ensure window stays on top when clicked
    def keep_on_top(event=None):
        menu_win.lift()
        menu_win.focus_force()

    menu_win.bind('<Button-1>', keep_on_top)
    menu_win.bind('<FocusIn>', keep_on_top)

    # Periodic check to ensure window stays on top
    def periodic_top_check():
        try:
            if menu_win.winfo_exists():
                menu_win.lift()
                # Schedule next check
                menu_win.after(5000, periodic_top_check)  # Check every 5 seconds
        except:
            pass  # Window was destroyed

    # Start periodic checking
    menu_win.after(5000, periodic_top_check)
    
    # Dynamic window size based on scaling - increased to show full UUID
    base_width, base_height = 900, 650  # Increased width for UUID visibility
    scaled_width = scale_dim(base_width)
    scaled_height = scale_dim(base_height)
    menu_win.geometry(f"{scaled_width}x{scaled_height}")
    menu_win.resizable(True, True)

    # Set minimum window size to ensure content is always visible
    min_width = max(850, int(scaled_width * 0.8))
    min_height = max(600, int(scaled_height * 0.8))
    menu_win.minsize(min_width, min_height)

    # Create variables for settings
    offline_mode = tk.BooleanVar(master=root, value=False)
    debug_text_color = tk.StringVar(value="cyan")
    refresh_interval = tk.IntVar(value=1)
    debug_tab_visible = tk.BooleanVar(value=False, master=menu_win)
    auto_refresh = tk.BooleanVar(value=True)

    # Load settings
    load_settings(debug_text_color, auto_refresh, refresh_interval)

    # --- DARK THEME FOR NOTEBOOK ---
    style = ttk.Style(menu_win)
    style.theme_use('default')
    style.configure(
        'TNotebook',
        background='#1a252f',
        borderwidth=0
    )
    style.configure(
        'TNotebook.Tab',
        background='#22303c',
        foreground='white',
        padding=[scale_dim(24), scale_dim(12)],
        font=get_scaled_font(12, 'bold')
    )

    # Configure dark theme for Combobox widgets
    style.configure(
        'TCombobox',
        fieldbackground='#555',
        background='#666',
        foreground='white',
        bordercolor='#777',
        arrowcolor='white',
        insertcolor='white',
        selectbackground='#0078d7',
        selectforeground='white'
    )
    style.map(
        'TCombobox',
        fieldbackground=[('readonly', '#555'), ('focus', '#666')],
        background=[('readonly', '#666'), ('focus', '#777')],
        foreground=[('readonly', 'white'), ('focus', 'white')],
        bordercolor=[('focus', '#0078d7')],
        arrowcolor=[('focus', '#ccc')]
    )
    style.map(
        'TNotebook.Tab',
        background=[('selected', '#2c3e50')],
        foreground=[('selected', '#00bfff'), ('active', '#00bfff')]
    )

    # Create notebook (tabbed interface)
    notebook = ttk.Notebook(menu_win, style='TNotebook')
    notebook.pack(fill="both", expand=True)

    # ----- Main Menu Tab -----
    main_frame = tk.Frame(notebook, bg="#1a252f")
    notebook.add(main_frame, text=get_text("main_menu"))

    # Configure full layout: 2 rows, 2 columns
    main_frame.grid_rowconfigure(0, weight=1)  # Top half (top card)
    main_frame.grid_rowconfigure(1, weight=1)  # Bottom half (left/right cards)
    main_frame.grid_columnconfigure(0, weight=1)  # Left card
    main_frame.grid_columnconfigure(1, weight=1)  # Right card

    # --- Scaled Fonts ---
    title_font = get_scaled_font(18, "bold")
    version_font = get_scaled_font(10)
    label_font = get_scaled_font(13, "bold")
    button_font = get_scaled_font(12)

    root.custom_fonts = {
        "title": title_font,
        "version": version_font,
        "label": label_font,
        "button": button_font,
    }

    # Initialize list to track widgets for dynamic font updates
    root.custom_font_widgets = []

    # --- Top Card Frame ---
    top_card = tk.Frame(main_frame, bg="#22303c", bd=2, relief="groove")
    top_card.grid(row=0, column=0, columnspan=2, 
                  padx=scale_dim(20), pady=scale_dim(20), sticky="nsew")
    top_card.grid_rowconfigure((0, 1, 2, 3), weight=1)
    top_card.grid_columnconfigure(0, weight=1)

    # --- Logo ---
    try:
        logo_path = get_local_logo_path()
        if logo_path and os.path.exists(logo_path):
            root.logo_img_original = Image.open(logo_path).convert("RGBA")
            resized = root.logo_img_original.copy()
            logo_size = (scale_dim(180), scale_dim(90))
            resized.thumbnail(logo_size, Image.LANCZOS)
            logo_img_displayed = ImageTk.PhotoImage(resized)
            root.logo_label = tk.Label(top_card, image=logo_img_displayed, bg="#22303c")
            root.logo_label.image = logo_img_displayed
            root.logo_label.grid(row=0, column=0, pady=(scale_dim(12), scale_dim(5)), sticky="n")
    except Exception as e:
        logging.error(f"Error loading logo for main menu: {e}")

    # --- Title and Version Labels ---
    title_label = tk.Label(
        top_card,
        text=get_text("app_title"),
        font=title_font,
        fg="#00bfff",
        bg="#22303c"
    )
    title_label.grid(row=1, column=0, pady=(0, scale_dim(5)), sticky="n")
    root.custom_font_widgets.append({'widget': title_label, 'base_size': 18, 'weight': 'bold'})

    version_label = tk.Label(
        top_card,
        text=f"{get_text('version')}: {VERSION}-{BUILD_TYPE} ({DEPLOYMENT_SCOPE})",
        font=version_font,
        fg="#b0b0b0",
        bg="#22303c"
    )
    version_label.grid(row=2, column=0, sticky="n")
    root.custom_font_widgets.append({'widget': version_label, 'base_size': 10, 'weight': 'normal'})

    game_version_label = tk.Label(
        top_card,
        text=f"{get_text('game_version')}: {game_version}",
        font=version_font,
        fg="#b0b0b0",
        bg="#22303c"
    )
    game_version_label.grid(row=3, column=0, pady=(0, scale_dim(10)), sticky="n")
    root.custom_font_widgets.append({'widget': game_version_label, 'base_size': 10, 'weight': 'normal'})

    # --- User Info Card (bottom-left) ---
    user_info_card = tk.Frame(main_frame, bg="#22303c", bd=3, relief="groove")
    user_info_card.grid(
        row=1,
        column=0,
        padx=(scale_dim(30), scale_dim(15)),
        pady=(0, scale_dim(30)),
        sticky="nsew"
    )

    # Explicitly give more weight so it expands vertically
    main_frame.grid_rowconfigure(1, weight=2)
    main_frame.grid_columnconfigure(0, weight=2)

    add_user_info_section(user_info_card)

    # --- Actions Card (bottom-right) ---
    actions_card = tk.Frame(main_frame, bg="#22303c", bd=2, relief="groove")
    actions_card.grid(row=1, column=1, 
                      padx=(scale_dim(10), scale_dim(20)), 
                      pady=(0, scale_dim(20)), sticky="nsew")

    tk.Label(
        actions_card,
        text=get_text("quick_actions"),
        font=label_font,
        fg="#00bfff",
        bg="#22303c"
    ).pack(anchor="w", pady=(0, scale_dim(8)), padx=scale_dim(12))

    btn_style = {
        "font": button_font,
        "width": scale_dim(18),
        "bg": "#2c5a7c",
        "fg": "white",
        "activebackground": "#3b7dab",
        "activeforeground": "white",
        "relief": "flat",
        "bd": 0,
        "highlightthickness": 0,
        "padx": scale_dim(6),
        "pady": scale_dim(6),
    }

    tk.Button(
        actions_card,
        text=get_text("about"),
        command=lambda: show_about(root),
        **btn_style
    ).pack(pady=scale_dim(5), anchor="w", padx=scale_dim(12))

    tk.Button(
        actions_card,
        text=get_text("send_feedback"),
        command=lambda: create_feedback_dialog(root),
        **btn_style
    ).pack(pady=scale_dim(5), anchor="w", padx=scale_dim(12))

    # Restart button with different styling to make it stand out
    restart_btn_style = btn_style.copy()
    restart_btn_style.update({
        "bg": "#e74c3c",  # Red background for restart
        "activebackground": "#c0392b",  # Darker red on hover
    })

    tk.Button(
        actions_card,
        text=get_text("restart_app"),
        command=lambda: restart_application(),
        **restart_btn_style
    ).pack(pady=scale_dim(5), anchor="w", padx=scale_dim(12))

    # Bind resize event AFTER widgets are created
    main_frame.bind("<Configure>", lambda e: on_main_menu_resize(e, root))

    # ----- Settings Tab -----
    settings_tab = tk.Frame(notebook, bg="#1a252f")
    notebook.add(settings_tab, text=get_text("settings"))

    # Create scrollable frame for settings
    settings_canvas = tk.Canvas(settings_tab, bg="#1a252f", highlightthickness=0)
    settings_scrollbar = tk.Scrollbar(settings_tab, orient="vertical", command=settings_canvas.yview)
    settings_scrollable_frame = tk.Frame(settings_canvas, bg="#1a252f")

    settings_scrollable_frame.bind(
        "<Configure>",
        lambda e: settings_canvas.configure(scrollregion=settings_canvas.bbox("all"))
    )

    settings_canvas.create_window((0, 0), window=settings_scrollable_frame, anchor="nw")
    settings_canvas.configure(yscrollcommand=settings_scrollbar.set)

    # Pack scrollable components
    settings_canvas.pack(side="left", fill="both", expand=True)
    settings_scrollbar.pack(side="right", fill="y")

    # Bind mousewheel to canvas
    def on_mousewheel(event):
        settings_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    settings_canvas.bind_all("<MouseWheel>", on_mousewheel)

    # ----- Support Tab -----
    support_tab = tk.Frame(notebook, bg="#1a252f")
    notebook.add(support_tab, text=get_text("support"))

    # Scaled button style for support tab
    support_btn_style = {
        "font": get_scaled_font(11),
        "bg": "#2c5a7c",
        "fg": "white",
        "activebackground": "#3b7dab",
        "activeforeground": "white",
        "relief": "flat",
        "width": scale_dim(25),
        "height": scale_dim(2),
    }

    # System info text
    sysinfo_text = (
        f"App Version: {VERSION}\n"
        f"Build Type: {BUILD_TYPE}\n"
        f"Deployment Scope: {DEPLOYMENT_SCOPE}\n"
        f"OS: {platform.system()} {platform.release()} ({platform.version()})\n"
        f"Machine: {platform.machine()}\n"
        f"Processor: {platform.processor()}\n"
        f"Timestamp: {datetime.now().isoformat()}\n"
    )

    # ----- System Info Frame (Top) -----
    sysinfo_frame = tk.LabelFrame(
        support_tab,
        text=get_text("system_details"),
        fg="white",
        bg="#1a252f",
        font=get_scaled_font(10, "bold"),
        bd=2,
        relief="groove",
        padx=scale_dim(10),
        pady=scale_dim(10),
    )
    sysinfo_frame.grid(row=0, column=0, columnspan=2, sticky="ew", 
                       padx=scale_dim(15), pady=(scale_dim(15), scale_dim(10)))

    sysinfo_box = tk.Text(
        sysinfo_frame,
        height=scale_dim(7),
        bg="#1a252f",
        fg="white",
        font=("Consolas", max(10 if SCALE_FACTOR >= 1.5 else 8, int(10 * SCALE_FACTOR))),
        relief="flat",
        wrap="word",
        state=tk.NORMAL,
    )
    sysinfo_box.insert(tk.END, sysinfo_text)
    sysinfo_box.configure(state=tk.DISABLED)
    sysinfo_box.pack(fill="both", expand=True)

    # ----- Shortcuts Frame -----
    shortcuts_frame = tk.LabelFrame(
        support_tab,
        text=get_text("shortcuts"),
        fg="white",
        bg="#1a252f",
        font=get_scaled_font(10, "bold"),
        bd=2,
        relief="groove",
        padx=scale_dim(10),
        pady=scale_dim(10),
    )
    shortcuts_frame.grid(row=1, column=0, columnspan=2, sticky="ew", 
                         padx=scale_dim(15), pady=scale_dim(5))

    def open_program_directory():
        program_dir = r"C:\Program Files\Harley's Studio\Star Citizen Kill Tracker"
        if os.path.exists(program_dir):
            subprocess.Popen(f'explorer "{program_dir}"')
        else:
            fallback_dir = os.path.dirname(os.path.abspath(__file__))
            subprocess.Popen(f'explorer "{fallback_dir}"')

    def open_localappdata_folder():
        target = os.path.expandvars(r"%LocalAppData%\Harley's Studio\Star Citizen Kill Tracker")
        if os.path.exists(target):
            subprocess.Popen(f'explorer "{target}"')
        else:
            local_appdata = os.getenv('LOCALAPPDATA')
            if local_appdata:
                subprocess.Popen(f'explorer "{local_appdata}"')

    program_dir_btn = tk.Button(
        shortcuts_frame,
        text="Open Program Directory",
        command=open_program_directory,
        **support_btn_style,
    )
    program_dir_btn.grid(row=0, column=0, 
                         padx=(scale_dim(5), scale_dim(10)), 
                         pady=scale_dim(5), sticky="ew")

    localappdata_btn = tk.Button(
        shortcuts_frame,
        text="Open LocalAppData Folder",
        command=open_localappdata_folder,
        **support_btn_style,
    )
    localappdata_btn.grid(row=0, column=1, 
                          padx=(scale_dim(10), scale_dim(5)), 
                          pady=scale_dim(5), sticky="ew")

    shortcuts_frame.grid_columnconfigure(0, weight=1)
    shortcuts_frame.grid_columnconfigure(1, weight=1)

    # ----- Support Ticket Frame -----
    ticket_frame = tk.LabelFrame(
        support_tab,
        text=get_text("need_help"),
        fg="white",
        bg="#1a252f",
        font=get_scaled_font(10, "bold"),
        bd=2,
        relief="groove",
        padx=scale_dim(10),
        pady=scale_dim(10),
    )
    ticket_frame.grid(row=2, column=0, columnspan=2, sticky="ew", 
                      padx=scale_dim(15), pady=(scale_dim(10), scale_dim(20)))

    support_hint = tk.Label(
        ticket_frame,
        text=(
            "Before creating a support ticket, a file containing system/app info will be created\n"
            "to help the support team assist you better."
        ),
        font=get_scaled_font(9),
        fg="white",
        bg="#1a252f",
        justify="left",
    )
    support_hint.pack(pady=(0, scale_dim(10)), anchor="w")

    def create_support_info_file():
        downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
        support_info_path = os.path.join(downloads_folder, "SC Kill Tracker[user_support_info].txt")
        with open(support_info_path, "w") as f:
            f.write("=== Star Citizen Kill Tracker Support Info ===\n\n")
            f.write(sysinfo_text)
            f.write("\nPlease attach this file when requesting support.\n")
        return support_info_path

    def open_discord_ticket():
        path = create_support_info_file()

        open_folder = show_message(
            "Open Support File Location",
            f"The support info file has been created:\n\n{path}\n\nWould you like to open the folder containing this file?",
            "question"
        )
        if open_folder:
            subprocess.Popen(f'explorer /select,"{path}"')

        response = show_message(
            "Discord Client or Browser",
            "Do you use the Discord desktop client?\n\n"
            "Click 'Yes' to open in the Discord app.\n"
            "Click 'No' to open in your web browser.",
            "question"
        )

        in_server = show_message(
            "Are You in the Server?",
            "Are you already in the Star Citizen Kill Tracker Discord server?",
            "question"
        )

        if not in_server:
            webbrowser.open("https://discord.gg/jxfHnGQqj7")
            show_message("Join the Server", "Please join the Discord server before submitting a ticket.", "info")

        discord_url = "https://discord.com/channels/1367284397400785027/1367289292854005800/1367296671570067517"
        if response == "yes":
            discord_client_url = "discord://discord.com/channels/1367284397400785027/1367289292854005800/1367296671570067517"
            webbrowser.open(discord_client_url)
        else:
            webbrowser.open(discord_url)

    discord_ticket_btn = tk.Button(
        ticket_frame,
        text="Create Support Ticket via Discord",
        command=open_discord_ticket,
        **support_btn_style,
    )
    discord_ticket_btn.pack(pady=scale_dim(5), fill="x")

    # Make main columns expandable
    support_tab.grid_columnconfigure(0, weight=1)
    support_tab.grid_columnconfigure(1, weight=1)

    # ----- Game Log Viewer Tab -----
    game_log_viewer_tab = tk.Frame(notebook, bg="#1a252f")
    debug_tab_frame = game_log_viewer_tab

    # Grid layout with 2 rows
    game_log_viewer_tab.grid_rowconfigure(0, weight=1)  # log expands
    game_log_viewer_tab.grid_columnconfigure(0, weight=1)

    # Font size variable (scaled) with better high-DPI support
    base_font_size = int(10 * SCALE_FACTOR)
    if SCALE_FACTOR >= 2.0:  # 4K+ displays
        base_font_size = max(14, base_font_size)
    elif SCALE_FACTOR >= 1.5:  # 1440p+ displays
        base_font_size = max(12, base_font_size)
    else:  # 1080p and below
        base_font_size = max(10, base_font_size)
    font_size_var = tk.IntVar(value=base_font_size)

    # Log text wrapper with fixed height constraint
    log_text_wrapper = tk.Frame(game_log_viewer_tab, bg="black")
    log_text_wrapper.grid(row=0, column=0, sticky="nsew", 
                          padx=scale_dim(5), pady=scale_dim(5))

    log_text = scrolledtext.ScrolledText(
        log_text_wrapper,
        wrap=tk.WORD,
        bg="black",
        fg=debug_text_color.get(),
        insertbackground="white",
        selectbackground="blue",
        font=("Consolas", font_size_var.get())
    )
    log_text.pack(fill="both", expand=True)
    log_text.config(state=tk.DISABLED)

    # Make log_text globally accessible for color changes
    globals()['log_text'] = log_text
    print("Log text widget created and made globally accessible")

    # Control panel docked to the bottom
    control_frame = tk.Frame(game_log_viewer_tab, bg="#1a252f")
    control_frame.grid(row=1, column=0, sticky="ew", 
                       padx=scale_dim(5), pady=(0, scale_dim(5)))

    # Left side controls
    left_controls = tk.Frame(control_frame, bg="#1a252f")
    left_controls.pack(side="left")

    refresh_btn = tk.Button(
        left_controls,
        text="Refresh Log",
        command=lambda: load_game_log_into_debug(log_text),
        bg="#2c5a7c",
        fg="white",
        font=get_scaled_font(10),
        width=scale_dim(12)
    )
    refresh_btn.pack(side="left", padx=(0, scale_dim(5)))

    auto_refresh_cb = tk.Checkbutton(
        left_controls,
        text="Auto-refresh",
        variable=auto_refresh,
        bg="#1a252f",
        fg="white",
        selectcolor="#1a252f",
        font=get_scaled_font(10)
    )
    auto_refresh_cb.pack(side="left")

    # Right side controls
    right_controls = tk.Frame(control_frame, bg="#1a252f")
    right_controls.pack(side="right")

    tk.Label(right_controls, text="Interval (s):", 
             bg="#1a252f", fg="white", font=get_scaled_font(10)).pack(side="left")
    interval_dropdown = ttk.Combobox(
        right_controls,
        textvariable=refresh_interval,
        values=[1, 2, 5, 10, 30],
        width=scale_dim(3),
        state="readonly",
        font=get_scaled_font(10)
    )
    interval_dropdown.pack(side="left", padx=(0, scale_dim(10)))

    # Add event handler for interval dropdown changes
    def on_interval_change(event=None):
        """Handle refresh interval dropdown changes"""
        try:
            new_interval = refresh_interval.get()
            print(f"Refresh interval changed to: {new_interval} seconds")
            # Save the new interval to settings
            save_settings(debug_text_color, auto_refresh, refresh_interval)
            # Restart auto-refresh with new interval if enabled
            if auto_refresh.get():
                start_auto_refresh()
        except Exception as e:
            print(f"Error handling interval change: {e}")

    interval_dropdown.bind("<<ComboboxSelected>>", on_interval_change)

    tk.Label(right_controls, text="Font Size:", 
             bg="#1a252f", fg="white", font=get_scaled_font(10)).pack(side="left")
    
    # Scaled font size options with better high-DPI support
    if SCALE_FACTOR >= 2.0:  # 4K+ displays
        min_font = max(12, int(8 * SCALE_FACTOR))
        max_font = max(20, int(30 * SCALE_FACTOR))
    elif SCALE_FACTOR >= 1.5:  # 1440p+ displays
        min_font = max(10, int(8 * SCALE_FACTOR))
        max_font = max(16, int(28 * SCALE_FACTOR))
    else:  # 1080p and below
        min_font = max(8, int(8 * SCALE_FACTOR))
        max_font = max(12, int(25 * SCALE_FACTOR))
    font_size_options = list(range(min_font, max_font + 1))
    
    font_size_selector = ttk.Combobox(
        right_controls,
        textvariable=font_size_var,
        values=font_size_options,
        width=scale_dim(3),
        state="readonly",
        font=get_scaled_font(10)
    )
    font_size_selector.pack(side="left")

    # Add event handler for font size dropdown changes
    def on_font_size_change(event=None):
        """Handle font size dropdown changes"""
        try:
            new_size = font_size_var.get()
            print(f"Font size changed to: {new_size}")
            # Apply the new font size immediately
            update_log_font_size()
        except Exception as e:
            print(f"Error handling font size change: {e}")

    font_size_selector.bind("<<ComboboxSelected>>", on_font_size_change)

    # Font size change handling
    def update_log_font_size(*args):
        log_text.config(font=("Consolas", font_size_var.get()))

    font_size_var.trace_add("write", update_log_font_size)

    # Function to toggle the Game Log Viewer tab visibility
    def toggle_game_log_viewer(*args):
        """Toggle the visibility of the Game Log Viewer tab."""
        tab_ids = notebook.tabs()
        is_tab_present = str(debug_tab_frame) in tab_ids

        if debug_tab_visible.get():
            if not is_tab_present:
                notebook.add(debug_tab_frame, text="Game Log Viewer")
            notebook.select(debug_tab_frame)  # Bring to front
            if log_text:
                load_game_log_into_debug(log_text)
            print("Showing Game Log Viewer Tab")
        else:
            if is_tab_present:
                notebook.forget(debug_tab_frame)  # Hide the tab
            print("Hiding Game Log Viewer Tab")

    # Auto-refresh logic with float-based interval
    def schedule_refresh():
        if auto_refresh.get() and str(game_log_viewer_tab) in notebook.tabs():
            load_game_log_into_debug(log_text)
            try:
                interval_ms = int(float(refresh_interval.get()) * 1000)
            except (ValueError, TypeError):
                interval_ms = 1000  # Fallback to 1 second
            menu_win.after(max(1, interval_ms), schedule_refresh)

    def start_auto_refresh(*args):
        if auto_refresh.get():
            schedule_refresh()

    auto_refresh.trace_add("write", start_auto_refresh)
    refresh_interval.trace_add("write", start_auto_refresh)
    debug_tab_visible.trace_add("write", toggle_game_log_viewer)

    # ===== Settings Tab =====
    # ========== Debug Section ==========
    debug_section = tk.LabelFrame(
        settings_scrollable_frame,
        text="Game Log Viewer Settings",
        fg="white", bg="#1a252f",
        font=get_scaled_font(10, "bold"),
        bd=2, relief="groove",
        padx=scale_dim(8), pady=scale_dim(8)
    )
    debug_section.pack(fill="x", padx=scale_dim(10), pady=(scale_dim(5), scale_dim(3)))

    # Show Game Log Viewer Checkbox
    tk.Checkbutton(
        debug_section,
        text="Show Game Log Viewer",
        variable=debug_tab_visible,
        bg="#1a252f", fg="white",
        activebackground="#1a252f", activeforeground="white",
        selectcolor="#1a252f",
        font=get_scaled_font(10)
    ).pack(anchor="w")

    # Color selection frame
    color_frame = tk.Frame(debug_section, bg="#1a252f")
    color_frame.pack(fill="x", pady=(scale_dim(10), 0))

    # Log Text Color Label
    tk.Label(
        color_frame,
        text="Log Text Color:",
        bg="#1a252f",
        fg="white",
        font=get_scaled_font(10)
    ).pack(anchor="w", pady=(0, scale_dim(2)))

    # Color selection sub-frame
    color_selection_frame = tk.Frame(color_frame, bg="#1a252f")
    color_selection_frame.pack(fill="x")

    # Import required modules
    import tkinter.colorchooser as colorchooser
    from tkinter import messagebox

    # Create color manager instance
    color_manager = ColorManager()
    
    # Define required variables
    log_text_color_var = tk.StringVar(value=debug_text_color.get())
    console_text_color_var = tk.StringVar(value="lime")  # Default console color
    custom_color_var = tk.StringVar(value="#00FFFF")
    
    # Function to apply color to log text widget
    def apply_log_color(color):
        try:
            if 'log_text' in globals():
                globals()['log_text'].config(fg=color)
                debug_text_color.set(color)
                save_settings(debug_text_color, auto_refresh, refresh_interval)
                print(f"Log text color applied: {color}")
            else:
                print("Warning: log_text widget not found - please open the Game Log Viewer tab first")
        except Exception as e:
            print(f"Error applying log color: {e}")

    # Function to apply color to console text widget
    def apply_console_color(color):
        try:
            if 'console_text' in globals() and 'console_input' in globals():
                globals()['console_text'].config(fg=color)
                globals()['console_input'].config(fg=color, insertbackground=color)
                # Save console color in settings
                settings = {}
                if os.path.exists(SETTINGS_FILE):
                    with open(SETTINGS_FILE, 'r') as f:
                        settings = json.load(f)
                settings['console_text_color'] = color
                with open(SETTINGS_FILE, 'w') as f:
                    json.dump(settings, f, indent=4)
                print(f"Console text color applied: {color}")
            else:
                print("Warning: console widgets not found - please open the Console tab first")
        except Exception as e:
            print(f"Error applying console color: {e}")
    
    # Predefined color dropdown for log text
    color_options = color_manager.get_color_options()
    color_dropdown = ttk.Combobox(
        color_selection_frame,
        textvariable=log_text_color_var,
        values=color_options,
        width=15,
        font=get_scaled_font(10),
        state="readonly"
    )
    color_dropdown.pack(side="left", padx=(0, scale_dim(10)))

    # Set current color and update preview
    default_color = log_text_color_var.get()
    color_dropdown.set(default_color)

    # Ensure dropdown is properly initialized
    def initialize_log_color_dropdown():
        """Initialize the log color dropdown with proper values and selection"""
        try:
            current_color = log_text_color_var.get()
            if current_color in color_options:
                color_dropdown.set(current_color)
            else:
                # Set to first available option if current color is not in list
                color_dropdown.set(color_options[0])
                log_text_color_var.set(color_options[0])
            print(f"Log color dropdown initialized with: {color_dropdown.get()}")
        except Exception as e:
            print(f"Error initializing log color dropdown: {e}")

    # Initialize the dropdown
    root.after(100, initialize_log_color_dropdown)
    color_preview = tk.Label(
        color_selection_frame,
        text="Preview",
        bg="#1a252f",
        fg=color_manager.get_text_color(default_color),
        font=get_scaled_font(10, "bold"),
        width=8,
        relief="sunken", bd=1
    )
    color_preview.pack(side="left", padx=(0, scale_dim(10)))

    # Update preview and text widgets when dropdown changes
    def on_log_color_change(event=None):
        try:
            selected = log_text_color_var.get()
            print(f"Log color dropdown changed to: {selected}")
            if selected == "custom":
                color_preview.config(fg=custom_color_var.get())
                apply_log_color(custom_color_var.get())
            else:
                color_hex = color_manager.get_text_color(selected)
                color_preview.config(fg=color_hex)
                apply_log_color(color_hex)
        except Exception as e:
            print(f"Error in log color change: {e}")

    color_dropdown.bind("<<ComboboxSelected>>", on_log_color_change)

    # Custom color picker for log text
    def open_log_color_picker():
        try:
            current_color = custom_color_var.get()
            print(f"Opening log color picker with current color: {current_color}")
            color_result = colorchooser.askcolor(
                color=current_color,
                title="Choose Custom Log Text Color",
                parent=debug_section
            )
            if color_result[1]:
                hex_color = color_result[1]
                custom_color_var.set(hex_color)

                # Add 'custom' to dropdown if not already present
                current_values = list(color_dropdown['values'])
                if "custom" not in current_values:
                    current_values.append("custom")
                    color_dropdown['values'] = current_values

                log_text_color_var.set("custom")
                color_dropdown.set("custom")
                color_preview.config(fg=hex_color)
                apply_log_color(hex_color)

                print(f"Custom log color selected: {hex_color}")
            else:
                print("Color picker cancelled")
        except Exception as e:
            print(f"Error opening log color picker: {e}")

    custom_color_btn = tk.Button(
        color_selection_frame,
        text="Custom Color",
        command=open_log_color_picker,
        bg="#2c3e50", fg="white",
        activebackground="#34495e", activeforeground="white",
        font=get_scaled_font(9),
        relief="raised", bd=2,
        padx=scale_dim(10),
        pady=scale_dim(2)
    )
    custom_color_btn.pack(side="left", padx=(0, scale_dim(10)))

    # Test button to verify color functionality
    test_log_color_btn = tk.Button(
        color_selection_frame,
        text="Test Color",
        command=lambda: apply_log_color(color_manager.get_text_color(log_text_color_var.get())),
        bg="#4CAF50", fg="white",
        activebackground="#45a049", activeforeground="white",
        font=get_scaled_font(9),
        relief="raised", bd=2,
        padx=scale_dim(8),
        pady=scale_dim(2)
    )
    test_log_color_btn.pack(side="left", padx=(0, scale_dim(10)))
    
    # Console color selection frame
    console_color_frame = tk.Frame(debug_section, bg="#1a252f")
    console_color_frame.pack(fill="x", pady=(scale_dim(10), 0))
    
    tk.Label(
        console_color_frame,
        text="Console Text Color:",
        bg="#1a252f",
        fg="white",
        font=get_scaled_font(10)
    ).pack(anchor="w", pady=(0, scale_dim(2)))
    
    console_color_selection_frame = tk.Frame(console_color_frame, bg="#1a252f")
    console_color_selection_frame.pack(fill="x")
    
    # Console color dropdown
    console_color_dropdown = ttk.Combobox(
        console_color_selection_frame,
        textvariable=console_text_color_var,
        values=color_options,
        width=15,
        font=get_scaled_font(10),
        state="readonly"
    )
    console_color_dropdown.pack(side="left", padx=(0, scale_dim(10)))

    # Ensure console dropdown is properly initialized
    def initialize_console_color_dropdown():
        """Initialize the console color dropdown with proper values and selection"""
        try:
            current_color = console_text_color_var.get()
            if current_color in color_options:
                console_color_dropdown.set(current_color)
            else:
                # Set to default lime if current color is not in list
                console_color_dropdown.set("lime")
                console_text_color_var.set("lime")
            print(f"Console color dropdown initialized with: {console_color_dropdown.get()}")
        except Exception as e:
            print(f"Error initializing console color dropdown: {e}")

    # Initialize the console dropdown
    root.after(100, initialize_console_color_dropdown)
    
    # Console color preview
    console_color_preview = tk.Label(
        console_color_selection_frame,
        text="Preview",
        bg="#1a252f",
        fg=color_manager.get_text_color("lime"),  # Default console color
        font=get_scaled_font(10, "bold"),
        width=8,
        relief="sunken", bd=1
    )
    console_color_preview.pack(side="left", padx=(0, scale_dim(10)))
    
    # Console custom color variable
    console_custom_color_var = tk.StringVar(value="#00FF00")  # Default lime
    
    # Update console color when dropdown changes
    def on_console_color_change(event=None):
        try:
            selected = console_text_color_var.get()
            print(f"Console color dropdown changed to: {selected}")
            if selected == "custom":
                console_color_preview.config(fg=console_custom_color_var.get())
                apply_console_color(console_custom_color_var.get())
            else:
                color_hex = color_manager.get_text_color(selected)
                console_color_preview.config(fg=color_hex)
                apply_console_color(color_hex)
        except Exception as e:
            print(f"Error in console color change: {e}")

    console_color_dropdown.bind("<<ComboboxSelected>>", on_console_color_change)
    
    # Custom color picker for console
    def open_console_color_picker():
        try:
            current_color = console_custom_color_var.get()
            print(f"Opening console color picker with current color: {current_color}")
            color_result = colorchooser.askcolor(
                color=current_color,
                title="Choose Custom Console Color",
                parent=debug_section
            )
            if color_result[1]:
                hex_color = color_result[1]
                console_custom_color_var.set(hex_color)

                # Add 'custom' to dropdown if not already present
                current_values = list(console_color_dropdown['values'])
                if "custom" not in current_values:
                    current_values.append("custom")
                    console_color_dropdown['values'] = current_values

                console_text_color_var.set("custom")
                console_color_dropdown.set("custom")
                console_color_preview.config(fg=hex_color)
                apply_console_color(hex_color)

                print(f"Custom console color selected: {hex_color}")
            else:
                print("Console color picker cancelled")
        except Exception as e:
            print(f"Error opening console color picker: {e}")
    
    console_custom_color_btn = tk.Button(
        console_color_selection_frame,
        text="Custom Color",
        command=open_console_color_picker,
        bg="#2c3e50", fg="white",
        activebackground="#34495e", activeforeground="white",
        font=get_scaled_font(9),
        relief="raised", bd=2,
        padx=scale_dim(10),
        pady=scale_dim(2)
    )
    console_custom_color_btn.pack(side="left", padx=(0, scale_dim(10)))

    # Test button to verify console color functionality
    test_console_color_btn = tk.Button(
        console_color_selection_frame,
        text="Test Color",
        command=lambda: apply_console_color(color_manager.get_text_color(console_text_color_var.get())),
        bg="#4CAF50", fg="white",
        activebackground="#45a049", activeforeground="white",
        font=get_scaled_font(9),
        relief="raised", bd=2,
        padx=scale_dim(8),
        pady=scale_dim(2)
    )
    test_console_color_btn.pack(side="left", padx=(0, scale_dim(10)))

    # Add a comprehensive dropdown test button
    def test_all_dropdowns():
        """Test all dropdown functionality"""
        try:
            print("\n=== Testing All Dropdown Functionality ===")

            # Test interval dropdown
            if 'interval_dropdown' in locals():
                original_interval = refresh_interval.get()
                test_intervals = [1, 2, 5, 10, 30]
                for test_val in test_intervals:
                    refresh_interval.set(test_val)
                    interval_dropdown.set(test_val)
                    print(f"✓ Interval dropdown test: {test_val}")
                refresh_interval.set(original_interval)
                interval_dropdown.set(original_interval)

            # Test font size dropdown
            if 'font_size_selector' in locals():
                original_font = font_size_var.get()
                test_font = font_size_options[len(font_size_options)//2]
                font_size_var.set(test_font)
                font_size_selector.set(test_font)
                print(f"✓ Font size dropdown test: {test_font}")
                font_size_var.set(original_font)
                font_size_selector.set(original_font)

            # Test color dropdowns
            if 'color_dropdown' in locals():
                original_color = log_text_color_var.get()
                test_color = "yellow"
                log_text_color_var.set(test_color)
                color_dropdown.set(test_color)
                print(f"✓ Log color dropdown test: {test_color}")
                log_text_color_var.set(original_color)
                color_dropdown.set(original_color)

            if 'console_color_dropdown' in locals():
                original_console = console_text_color_var.get()
                test_console = "cyan"
                console_text_color_var.set(test_console)
                console_color_dropdown.set(test_console)
                print(f"✓ Console color dropdown test: {test_console}")
                console_text_color_var.set(original_console)
                console_color_dropdown.set(original_console)

            print("=== All Dropdown Tests Completed Successfully ===\n")
            show_message("Dropdown Test", "All dropdown boxes tested successfully! Check console for details.", "info")

        except Exception as e:
            print(f"Error during dropdown testing: {e}")
            show_message("Dropdown Test Error", f"Error testing dropdowns: {e}", "error")

    # Add test button for dropdowns
    test_dropdowns_btn = tk.Button(
        console_color_selection_frame,
        text="Test All Dropdowns",
        command=test_all_dropdowns,
        bg="#9C27B0", fg="white",
        activebackground="#7B1FA2", activeforeground="white",
        font=get_scaled_font(9),
        relief="raised", bd=2,
        padx=scale_dim(8),
        pady=scale_dim(2)
    )
    test_dropdowns_btn.pack(side="left", padx=(scale_dim(10), 0))
    
    # Load console color from settings
    def load_console_color():
        try:
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, 'r') as f:
                    settings = json.load(f)
                    console_color = settings.get('console_text_color', 'lime')
                    console_text_color_var.set(console_color)
                    console_color_dropdown.set(console_color)
                    console_color_preview.config(fg=color_manager.get_text_color(console_color))
                    # Apply color to console widgets if they exist
                    if 'console_text' in globals():
                        globals()['console_text'].config(fg=color_manager.get_text_color(console_color))
                    if 'console_input' in globals():
                        globals()['console_input'].config(fg=color_manager.get_text_color(console_color),
                                            insertbackground=color_manager.get_text_color(console_color))
                    print(f"Console color loaded from settings: {console_color}")
        except Exception as e:
            print(f"Error loading console color: {e}")

    # Call to load console color
    load_console_color()

    # Function to initialize colors when widgets are available
    def initialize_widget_colors():
        """Initialize colors for widgets when they become available"""
        try:
            # Initialize log text color
            if 'log_text' in globals():
                current_log_color = debug_text_color.get()
                color_hex = color_manager.get_text_color(current_log_color)
                globals()['log_text'].config(fg=color_hex)
                print(f"Initialized log text color: {current_log_color}")

            # Initialize console colors
            if 'console_text' in globals() and 'console_input' in globals():
                # Load console color from settings
                console_color = "lime"  # default
                if os.path.exists(SETTINGS_FILE):
                    with open(SETTINGS_FILE, 'r') as f:
                        settings = json.load(f)
                        console_color = settings.get('console_text_color', 'lime')

                color_hex = color_manager.get_text_color(console_color)
                globals()['console_text'].config(fg=color_hex)
                globals()['console_input'].config(fg=color_hex, insertbackground=color_hex)
                print(f"Initialized console colors: {console_color}")
        except Exception as e:
            print(f"Error initializing widget colors: {e}")

    # Schedule color initialization after widgets are created
    root.after(500, initialize_widget_colors)

    # Comprehensive dropdown validation and initialization
    def validate_all_dropdowns():
        """Validate and ensure all dropdown boxes are working properly"""
        try:
            print("=== Validating All Dropdown Boxes ===")

            # Validate interval dropdown
            if 'interval_dropdown' in locals():
                current_interval = refresh_interval.get()
                if current_interval not in [1, 2, 5, 10, 30]:
                    refresh_interval.set(1)
                    interval_dropdown.set(1)
                print(f"✓ Interval dropdown: {interval_dropdown.get()}")

            # Validate font size dropdown
            if 'font_size_selector' in locals():
                current_font = font_size_var.get()
                if current_font not in font_size_options:
                    font_size_var.set(font_size_options[0])
                    font_size_selector.set(font_size_options[0])
                print(f"✓ Font size dropdown: {font_size_selector.get()}")

            # Validate color dropdowns
            if 'color_dropdown' in locals():
                current_log_color = log_text_color_var.get()
                if current_log_color not in color_options and current_log_color != "custom":
                    log_text_color_var.set("cyan")
                    color_dropdown.set("cyan")
                print(f"✓ Log color dropdown: {color_dropdown.get()}")

            if 'console_color_dropdown' in locals():
                current_console_color = console_text_color_var.get()
                if current_console_color not in color_options and current_console_color != "custom":
                    console_text_color_var.set("lime")
                    console_color_dropdown.set("lime")
                print(f"✓ Console color dropdown: {console_color_dropdown.get()}")

            print("=== All Dropdown Validation Complete ===")

        except Exception as e:
            print(f"Error during dropdown validation: {e}")

    # Schedule dropdown validation
    root.after(1000, validate_all_dropdowns)

    def update_log_text_color(*_):
        try:
            selected_color_name = log_text_color_var.get()
            if 'log_text' in globals():
                color_hex = color_manager.get_text_color(selected_color_name)
                globals()['log_text'].config(fg=color_hex)
                print(f"Log text color updated via trace: {selected_color_name} -> {color_hex}")
        except Exception as e:
            print(f"Error updating log text color: {e}")

    # Connect the function to the variable
    log_text_color_var.trace_add("write", update_log_text_color)

    # Add tab change event handler to ensure colors are applied when switching tabs
    def on_tab_changed(event):
        """Handle tab change events to ensure colors are properly applied"""
        try:
            selected_tab = event.widget.tab('current')['text']
            print(f"Tab changed to: {selected_tab}")

            # Re-initialize colors when switching to relevant tabs
            if selected_tab == get_text("console"):
                root.after(100, lambda: apply_console_color(color_manager.get_text_color(console_text_color_var.get())))
            elif "Log" in selected_tab or "Debug" in selected_tab:
                root.after(100, lambda: apply_log_color(color_manager.get_text_color(log_text_color_var.get())))
        except Exception as e:
            print(f"Error in tab change handler: {e}")

    # Bind tab change event
    notebook.bind("<<NotebookTabChanged>>", on_tab_changed)

    # Language selection
    language_section = tk.LabelFrame(
        settings_scrollable_frame,
        text="Language Settings",
        fg="white", bg="#1a252f",
        font=get_scaled_font(10, "bold"),
        bd=2, relief="groove",
        padx=scale_dim(8), pady=scale_dim(8)
    )

    language_section.pack(fill="x", padx=scale_dim(10), pady=(scale_dim(3), scale_dim(3)))
    
    current_lang = tk.StringVar(value=CURRENT_LANGUAGE)

    tk.Label(
        language_section,
        text=f"{get_text('language')}:",
        bg="#1a252f", fg="white",
        font=get_scaled_font(10)
    ).pack(anchor="w", pady=(0, scale_dim(2)))

    # Remove duplicate label
    language_options = [
        ("English", "en"),
        ("Español", "es"),
        ("Français", "fr"),
        ("Deutsch", "de")
    ]

    language_frame = tk.Frame(language_section, bg="#1a252f")
    language_frame.pack(anchor="w", pady=(0, scale_dim(5)))

    for i, (lang_name, lang_code) in enumerate(language_options):
        tk.Radiobutton(
            language_frame,
            text=lang_name,
            variable=current_lang,
            value=lang_code,
            bg="#1a252f", fg="white",
            selectcolor="#1a252f",
            activebackground="#1a252f", activeforeground="white",
            font=get_scaled_font(10)
        ).grid(row=i//2, column=i%2, sticky="w", padx=(0, scale_dim(20)))

    def apply_language():
        new_lang = current_lang.get()
        set_language(new_lang)
        show_message(
            get_text("language"),
            "Language updated! Please restart the application for full effect.",
            "info"
        )

    apply_lang_btn = tk.Button(
        language_section,
        text=get_text("apply"),
        command=apply_language,
        bg="#2c5a7c",
        fg="white",
        font=get_scaled_font(10),
        width=scale_dim(10)
    )
    apply_lang_btn.pack(anchor="w", pady=(scale_dim(3), 0))

    # ====== Network Section ======
    offline_mode_flag = tk.BooleanVar(value=get_offline_mode())

    network_section = tk.LabelFrame(
        settings_scrollable_frame,
        text="Network Settings",
        fg="white", bg="#1a252f",
        font=get_scaled_font(10, "bold"),
        bd=2, relief="groove",
        padx=scale_dim(8), pady=scale_dim(8)
    )
    network_section.pack(fill="x", padx=scale_dim(10), pady=(scale_dim(3), scale_dim(3)))

    # --- Status Indicator ---
    status_frame = tk.Frame(network_section, bg="#1a252f")
    status_frame.pack(anchor="w", padx=scale_dim(3), pady=(0, scale_dim(5)))

    status_label = tk.Label(
        status_frame,
        text="Status:",
        fg="white", bg="#1a252f",
        font=get_scaled_font(10, "bold")
    )
    status_label.pack(side="left")

    status_canvas = tk.Canvas(
        status_frame,
        width=scale_dim(20), height=scale_dim(20),
        bg="#1a252f", highlightthickness=0
    )
    status_canvas.pack(side="left", padx=(scale_dim(8), 0))

    circle_size = scale_dim(16)
    margin = (scale_dim(20) - circle_size) // 2
    status_circle = status_canvas.create_oval(
        margin, margin, margin + circle_size, margin + circle_size, fill="green"
    )

    def update_status_indicator():
        if offline_mode_flag.get():
            status_canvas.itemconfig(status_circle, fill="red")
            status_label.config(text="Status: Offline", fg="red")
        else:
            status_canvas.itemconfig(status_circle, fill="green")
            status_label.config(text="Status: Online", fg="lime")

    def offline_mode_toggle():
        is_offline = offline_mode_flag.get()
        set_offline_mode(is_offline)

        if is_offline:
            show_message(
                "Offline Mode Enabled",
                "Offline mode disables all network connections and Discord webhook data sending.",
                "info"
            )
            logging.info("Offline mode enabled by user.")
        else:
            show_message(
                "Offline Mode Disabled",
                "Network connections and Discord webhook data sending are now enabled.",
                "info"
            )
            logging.info("Offline mode disabled by user.")

        update_status_indicator()

    # --- Offline Mode Checkbox ---
    offline_chk = tk.Checkbutton(
        network_section,
        text="Offline Mode (Disable Network Connections & Discord Webhook)",
        variable=offline_mode_flag,
        command=offline_mode_toggle,
        bg="#1a252f", fg="white",
        selectcolor="#1a252f",
        activebackground="#1a252f", activeforeground="white",
        font=get_scaled_font(11),
        wraplength=scale_dim(550), justify="left"
    )
    offline_chk.pack(anchor="w", pady=(0, scale_dim(5)), padx=scale_dim(3))

    # --- Info Label ---
    info_label = tk.Label(
        network_section,
        text="When offline mode is enabled, no data will be sent to Discord webhooks or external servers.",
        font=get_scaled_font(9),
        fg="gray", bg="#1a252f",
        wraplength=scale_dim(600), justify="left"
    )
    info_label.pack(anchor="w", padx=scale_dim(3))

    # Initialize UI to reflect current memory state
    update_status_indicator()

    # ===== Overlay Settings Section =====
    overlay_enabled_flag = tk.BooleanVar(value=get_overlay_enabled())

    overlay_section = tk.LabelFrame(
        settings_scrollable_frame,
        text="Overlay Settings",
        fg="white", bg="#1a252f",
        font=get_scaled_font(10, "bold"),
        bd=2, relief="groove",
        padx=scale_dim(8), pady=scale_dim(8)
    )
    overlay_section.pack(fill="x", padx=scale_dim(10), pady=(scale_dim(3), scale_dim(5)))

    def is_offline_and_overlay_disabled():
        return offline_mode_flag.get() and not overlay_enabled_flag.get()

    def overlay_enabled_toggle():
        if is_offline_and_overlay_disabled():
            overlay_enabled_flag.set(True)
            messagebox.showwarning("Warning", "Cannot disable overlay while offline mode is enabled.")
            return

        enabled = overlay_enabled_flag.get()
        on_overlay_toggle(enabled)

        if enabled:
            messagebox.showinfo("Overlay Enabled", "Overlay display is now enabled.")
            logging.info("Overlay enabled by user.")
        else:
            messagebox.showinfo("Overlay Disabled", "Overlay display is now disabled.")
            logging.info("Overlay disabled by user.")

    overlay_chk = tk.Checkbutton(
        overlay_section,
        text="Enable Overlay",
        variable=overlay_enabled_flag,
        command=overlay_enabled_toggle,
        bg="#1a252f", fg="white",
        selectcolor="#1a252f",
        activebackground="#1a252f", activeforeground="white",
        font=get_scaled_font(11)
    )
    overlay_chk.pack(anchor="w", pady=(0, scale_dim(5)), padx=scale_dim(3))

    note_label = tk.Label(
        overlay_section,
        text="* Overlay cannot be disabled while offline mode is enabled.",
        bg="#1a252f", fg="white", font=("Segoe UI", 9, "italic")
    )
    note_label.pack(anchor="w", padx=3)

    # ----- App Console Tab -----
    console_tab = tk.Frame(notebook, bg="#1a252f")
    notebook.add(console_tab, text=get_text("console"))

    # Console layout
    console_tab.grid_rowconfigure(0, weight=1)
    console_tab.grid_columnconfigure(0, weight=1)

    # Console output area
    console_output_frame = tk.Frame(console_tab, bg="black")
    console_output_frame.grid(row=0, column=0, sticky="nsew",
                              padx=scale_dim(5), pady=scale_dim(5))

    console_text = scrolledtext.ScrolledText(
        console_output_frame,
        wrap=tk.WORD,
        bg="black",
        fg="lime",
        insertbackground="lime",
        selectbackground="darkgreen",
        font=("Consolas", max(10 if SCALE_FACTOR >= 1.5 else 8, int(10 * SCALE_FACTOR)))
    )
    console_text.pack(fill="both", expand=True)
    console_text.config(state=tk.DISABLED)

    # Make console_text globally accessible for output redirection and color changes
    global app_console_widget
    app_console_widget = console_text
    globals()['console_text'] = console_text
    print("Console text widget created and made globally accessible")

    # Populate console with any buffered output from startup
    def populate_startup_output():
        """Add any buffered console output from before the widget was created"""
        try:
            console_text.config(state=tk.NORMAL)

            # Add from memory buffer if available
            if console_buffer:
                console_text.insert(tk.END, "=== Application Startup Log (from memory) ===\n")
                for line in console_buffer:
                    console_text.insert(tk.END, f"{line}\n")
                console_text.insert(tk.END, "\n=== Live Console Output ===\n")
            elif stdout_redirector.buffer:
                # Fallback to stdout buffer if memory buffer is empty
                console_text.insert(tk.END, "=== Application Startup Log ===\n")
                for line in stdout_redirector.buffer:
                    if line.strip():
                        console_text.insert(tk.END, line)
                console_text.insert(tk.END, "\n=== Live Console Output ===\n")

            console_text.see(tk.END)
            console_text.config(state=tk.DISABLED)
        except Exception as e:
            logging.warning(f"Failed to populate startup output: {e}")

    # Populate startup output after a short delay to ensure widget is ready
    root.after(100, populate_startup_output)

    # Console input area
    console_input_frame = tk.Frame(console_tab, bg="#1a252f")
    console_input_frame.grid(row=1, column=0, sticky="ew",
                             padx=scale_dim(5), pady=(0, scale_dim(5)))

    tk.Label(console_input_frame, text="Command:",
             bg="#1a252f", fg="white", font=get_scaled_font(10)).pack(side="left")

    console_input = tk.Entry(
        console_input_frame,
        bg="black",
        fg="lime",
        insertbackground="lime",
        font=("Consolas", max(10 if SCALE_FACTOR >= 1.5 else 8, int(10 * SCALE_FACTOR)))
    )

    # Make console_input globally accessible for color changes
    globals()['console_input'] = console_input
    print("Console input widget created and made globally accessible")
    console_input.pack(side="left", fill="x", expand=True, padx=(scale_dim(5), scale_dim(5)))

    def execute_console_command(event=None):
        command = console_input.get().strip()
        if not command:
            return

        # Add command to console
        console_text.config(state=tk.NORMAL)
        console_text.insert(tk.END, f"> {command}\n")

        try:
            # Execute basic commands
            if command.lower() == "help":
                help_text = """Available Commands:
- help: Show this help message
- clear: Clear console widget
- scale: Show current scale factor
- test_scaling: Test scaling information
- version: Show app version
- language [code]: Set language (en, es, fr, de)
- overlay_test: Test overlay display
- debug: Print a test debug message
- buffer_size: Show console widget line count
- memory: Show memory buffer statistics
- show_memory: Show last 20 lines from memory buffer
- load_memory: Load full memory buffer into console
- save_log: Save both widget and memory logs to desktop
"""
                console_text.insert(tk.END, help_text)
            elif command.lower() == "clear":
                console_text.delete(1.0, tk.END)
                console_text.config(state=tk.DISABLED)
                console_input.delete(0, tk.END)
                return
            elif command.lower() == "scale":
                scale = get_scale_factor()
                console_text.insert(tk.END, f"Current scale factor: {scale:.2f}\n")
            elif command.lower() == "test_scaling":
                info = test_scaling_info()
                console_text.insert(tk.END, f"{info}\n")
            elif command.lower() == "version":
                console_text.insert(tk.END, f"SC Kill Tracker {VERSION}-{BUILD_TYPE} ({DEPLOYMENT_SCOPE})\n")
            elif command.lower().startswith("language "):
                lang_code = command.split(" ", 1)[1].strip()
                if lang_code in TRANSLATIONS:
                    set_language(lang_code)
                    console_text.insert(tk.END, f"Language set to: {lang_code}\n")
                    console_text.insert(tk.END, "Note: Restart required for full effect\n")
                else:
                    console_text.insert(tk.END, f"Unknown language: {lang_code}\n")
                    console_text.insert(tk.END, "Available: en, es, fr, de\n")
            elif command.lower() == "overlay_test":
                console_text.insert(tk.END, "Testing overlay display...\n")
                # Test overlay if available
                if 'death_overlay' in globals() and death_overlay:
                    death_overlay.show_death_log({
                        'timestamp': datetime.now().strftime("%H:%M:%S"),
                        'victim': 'TestPlayer',
                        'victim_id': '12345',
                        'killer': 'Console',
                        'killer_id': '00000',
                        'zone': 'Test Zone',
                        'weapon': 'Console Command',
                        'damage_type': 'Debug',
                        'class': 'Test'
                    }, "🔧 Console Test")
                    console_text.insert(tk.END, "Overlay test sent!\n")
                else:
                    console_text.insert(tk.END, "Overlay not available\n")
            elif command.lower() == "debug":
                console_text.insert(tk.END, "Printing debug test message...\n")
                print("DEBUG: This is a test message from console command")
                logging.info("Console debug command executed")
            elif command.lower() == "buffer_size":
                lines = console_text.get("1.0", tk.END).split('\n')
                console_text.insert(tk.END, f"Console buffer contains {len(lines)} lines\n")
            elif command.lower() == "save_log":
                try:
                    import os
                    from datetime import datetime

                    # Save both console widget content and memory buffer
                    widget_content = console_text.get("1.0", tk.END)
                    memory_content = "\n".join(console_buffer) if console_buffer else "No memory buffer content"

                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

                    # Save widget content
                    filename_widget = f"console_widget_{timestamp}.txt"
                    filepath_widget = os.path.join(os.path.expanduser("~"), "Desktop", filename_widget)
                    with open(filepath_widget, 'w', encoding='utf-8') as f:
                        f.write("=== Console Widget Content ===\n")
                        f.write(widget_content)

                    # Save memory buffer content
                    filename_memory = f"console_memory_{timestamp}.txt"
                    filepath_memory = os.path.join(os.path.expanduser("~"), "Desktop", filename_memory)
                    with open(filepath_memory, 'w', encoding='utf-8') as f:
                        f.write("=== Console Memory Buffer ===\n")
                        f.write(memory_content)

                    console_text.insert(tk.END, f"Console logs saved:\n")
                    console_text.insert(tk.END, f"Widget: {filepath_widget}\n")
                    console_text.insert(tk.END, f"Memory: {filepath_memory}\n")
                except Exception as e:
                    console_text.insert(tk.END, f"Failed to save log: {e}\n")
            elif command.lower() == "memory":
                console_text.insert(tk.END, f"Memory buffer contains {len(console_buffer)} lines\n")
                console_text.insert(tk.END, f"Memory limit: {console_memory_limit} lines\n")
            elif command.lower() == "show_memory":
                console_text.insert(tk.END, "=== Recent Memory Buffer (last 20 lines) ===\n")
                recent_lines = console_buffer[-20:] if len(console_buffer) >= 20 else console_buffer
                for line in recent_lines:
                    console_text.insert(tk.END, f"{line}\n")
                console_text.insert(tk.END, "=== End Memory Buffer ===\n")
            elif command.lower() == "load_memory":
                console_text.insert(tk.END, "Loading full memory buffer into console...\n")
                console_text.config(state=tk.NORMAL)
                console_text.delete(1.0, tk.END)
                console_text.insert(tk.END, f"SC Kill Tracker Console {VERSION}\n")
                console_text.insert(tk.END, "=== Full Memory Buffer ===\n")
                for line in console_buffer:
                    console_text.insert(tk.END, f"{line}\n")
                console_text.insert(tk.END, "=== End Memory Buffer ===\n")
                console_text.insert(tk.END, "Type 'help' for available commands\n\n")
                console_text.see(tk.END)
                console_text.config(state=tk.DISABLED)
                console_input.delete(0, tk.END)
                return
            else:
                console_text.insert(tk.END, f"Unknown command: {command}\n")
                console_text.insert(tk.END, "Type 'help' for available commands\n")
        except Exception as e:
            console_text.insert(tk.END, f"Error: {e}\n")

        console_text.insert(tk.END, "\n")
        console_text.config(state=tk.DISABLED)
        console_text.see(tk.END)
        console_input.delete(0, tk.END)

    console_input.bind("<Return>", execute_console_command)

    execute_btn = tk.Button(
        console_input_frame,
        text="Execute",
        command=execute_console_command,
        bg="#2c5a7c",
        fg="white",
        font=get_scaled_font(10),
        width=scale_dim(8)
    )
    execute_btn.pack(side="right")

    # Add welcome message to console
    console_text.config(state=tk.NORMAL)
    console_text.insert(tk.END, f"SC Kill Tracker Console {VERSION}\n")
    console_text.insert(tk.END, "Type 'help' for available commands\n")
    console_text.insert(tk.END, "This console shows live application output and debug information.\n\n")
    console_text.config(state=tk.DISABLED)

    # Center window
    menu_win.update_idletasks()
    x = (menu_win.winfo_screenwidth() - menu_win.winfo_width()) // 2
    y = (menu_win.winfo_screenheight() - menu_win.winfo_height()) // 2
    menu_win.geometry(f"+{x}+{y}")

    # --- Auto-refresh logic for main menu ---
    def auto_refresh_main_menu():
        try:
            game_version_label.config(text=f"SC Game Version: {game_version}")
        except Exception:
            pass
        # Schedule next refresh (as fast as Tkinter allows)
        menu_win.after(1, auto_refresh_main_menu)  # 1 ms interval

    auto_refresh_main_menu()  # Start the auto-refresh loop

    # Center window
    menu_win.update_idletasks()
    x = (menu_win.winfo_screenwidth() - menu_win.winfo_width()) // 2
    y = (menu_win.winfo_screenheight() - menu_win.winfo_height()) // 2
    menu_win.geometry(f"+{x}+{y}")

    return menu_win
# ===== In-Memory Overlay State =====
app_settings = {}  # ensure it's a dictionary
app_settings.setdefault("overlay_enabled", True)  # default to True

def set_overlay_enabled(state: bool):
    app_settings["overlay_enabled"] = state
    logging.info(f"[App State] Overlay enabled set to: {state}")

def get_overlay_enabled() -> bool:
    return app_settings.get("overlay_enabled", True)

def is_overlay_enabled() -> bool:
    return get_overlay_enabled()

def on_overlay_toggle(enabled: bool):
    set_overlay_enabled(enabled)  # update in-memory app state
    death_overlay.set_overlay_enabled(enabled)  # update overlay widget

# ===== In-Memory App State =====
app_settings = {
    "offline_mode": False  # default initial value
}

def set_offline_mode(state: bool):
    app_settings["offline_mode"] = state
    logging.info(f"[App State] Offline mode set to: {state}")

def get_offline_mode() -> bool:
    return app_settings.get("offline_mode", False)

def is_offline_mode() -> bool:
    """Convenience method to check if offline mode is active"""
    return get_offline_mode()

STATUS_MESSAGES = [
    "Downloading logo.png",
    "Initializing modules",
    "Loading UI components",
    "Fetching configuration",
    f"Starting SC Kill Tracker [Version info : {VERSION}-{BUILD_TYPE}({DEPLOYMENT_SCOPE})]"
]

class HardcodedSpinner(QWidget):
    def __init__(self, parent=None, radius=30, line_width=4):
        super().__init__(parent)
        self.angle = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.rotate)
        self.timer.start(50)
        self.radius = radius
        self.line_width = line_width
        self.setFixedSize(radius * 2, radius * 2)

    def rotate(self):
        self.angle = (self.angle + 30) % 360
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        center = QPointF(self.width() / 2, self.height() / 2)
        painter.translate(center)
        painter.rotate(self.angle)

        # Draw the spinner arc
        pen = QPen(QColor("#00BFFF"))  # Bright cyan
        pen.setWidth(self.line_width)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)

        rect = QRectF(-self.radius + self.line_width,
                      -self.radius + self.line_width,
                      2 * (self.radius - self.line_width),
                      2 * (self.radius - self.line_width))

        painter.drawArc(rect, 0, 120 * 16)  # A 120-degree arc (1/3 circle)


class ModernSplashScreen(QSplashScreen):
    def __init__(self):
        # Create a modern gradient background
        pixmap = QPixmap(450, 550)
        self.create_modern_background(pixmap)
        super().__init__(pixmap, Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)

        self.setFixedSize(450, 550)

        # Main transparent widget
        self.main_widget = QWidget(self)
        self.main_widget.setStyleSheet("""
            QWidget {
                background: transparent;
                color: white;
            }
        """)
        self.main_widget.setGeometry(0, 0, 450, 550)

        layout = QVBoxLayout(self.main_widget)
        layout.setContentsMargins(30, 40, 30, 30)
        layout.setSpacing(10)

        # Logo
        self.logo_label = QLabel()
        self.logo_label.setAlignment(Qt.AlignCenter)
        self.logo_label.setStyleSheet("background: transparent;")
        self.load_logo()
        layout.addWidget(self.logo_label)

        # Title
        title_label = QLabel("Star Citizen Kill Tracker")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Segoe UI", 22, QFont.Bold))
        title_label.setStyleSheet("color: white; background: transparent; margin: 0;")
        layout.addWidget(title_label)

        # Subtitle
        subtitle_label = QLabel("Advanced Performance Tracking")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setFont(QFont("Segoe UI", 11))
        subtitle_label.setStyleSheet("color: rgba(255, 255, 255, 0.8); background: transparent;")
        layout.addWidget(subtitle_label)

        # Spacer
        layout.addStretch(1)

        # Loading container
        loading_container = QWidget()
        loading_container.setStyleSheet("background: transparent;")
        loading_layout = QVBoxLayout(loading_container)
        loading_layout.setAlignment(Qt.AlignCenter)
        loading_layout.setContentsMargins(0, 0, 0, 0)
        loading_layout.setSpacing(10)

        self.loading_spinner = HardcodedSpinner()
        loading_layout.addWidget(self.loading_spinner, alignment=Qt.AlignCenter)

        self.loading_label = QLabel("Loading")
        self.loading_label.setAlignment(Qt.AlignCenter)
        self.loading_label.setFont(QFont("Segoe UI", 12))
        self.loading_label.setStyleSheet("color: white; background: transparent;")
        loading_layout.addWidget(self.loading_label)

        self.status_label = QLabel("Initializing...")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setFont(QFont("Segoe UI", 10))
        self.status_label.setStyleSheet("""
            color: rgba(255, 255, 255, 0.9);
            background-color: rgba(255, 255, 255, 0.1);
            padding: 8px 16px;
            border-radius: 10px;
        """)
        loading_layout.addWidget(self.status_label)

        layout.addWidget(loading_container)

        # Spacer
        layout.addStretch(2)

        # Version info
        version_label = QLabel(f"Version {VERSION} • {BUILD_TYPE} • {DEPLOYMENT_SCOPE}")
        version_label.setAlignment(Qt.AlignCenter)
        version_label.setFont(QFont("Segoe UI", 9))
        version_label.setStyleSheet("color: rgba(255, 255, 255, 0.6); background: transparent;")
        layout.addWidget(version_label)

        # Animation variables
        self.dot_count = 0
        self.status_index = 0

        # Text animation timer
        self.text_timer = QTimer()
        self.text_timer.timeout.connect(self.update_text)
        self.text_timer.start(600)

        # Drop shadow for modern look
        self.add_shadow_effect()

        # Center splash screen on screen
        self.center_on_screen()


    def create_modern_background(self, pixmap):
        """Create a modern gradient background with subtle effects"""
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)

        # Create modern dark gradient
        gradient = QLinearGradient(0, 0, 0, pixmap.height())
        gradient.setColorAt(0, QColor(30, 39, 51))      # Dark blue-gray top
        gradient.setColorAt(0.6, QColor(20, 27, 35))    # Darker middle
        gradient.setColorAt(1, QColor(15, 20, 26))      # Very dark bottom

        painter.fillRect(pixmap.rect(), gradient)

        # Add subtle accent border
        painter.setPen(QPen(QColor(0, 120, 215, 100), 2))  # Windows 11 accent with transparency
        painter.drawRoundedRect(1, 1, pixmap.width()-2, pixmap.height()-2, 12, 12)

        painter.end()

    def add_shadow_effect(self):
        """Add modern drop shadow effect"""
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(25)
        shadow.setXOffset(0)
        shadow.setYOffset(8)
        shadow.setColor(QColor(0, 0, 0, 180))
        self.setGraphicsEffect(shadow)

    def load_logo(self):
        """Load logo with modern error handling"""
        try:
            response = requests.get(LOGO_URL, timeout=5)
            response.raise_for_status()
            image_data = BytesIO(response.content)
            pil_logo = Image.open(image_data)
            pil_logo.thumbnail((320, 120), Image.LANCZOS)

            # Convert to QPixmap
            pil_logo = pil_logo.convert('RGBA')
            data = pil_logo.tobytes('raw', 'RGBA')
            from PySide6.QtGui import QImage
            qimage = QImage(data, pil_logo.width, pil_logo.height, QImage.Format_RGBA8888)
            pixmap = QPixmap.fromImage(qimage)

            self.logo_label.setPixmap(pixmap)
            logging.info("Logo loaded successfully")
        except Exception as e:
            logging.error(f"Failed to load logo: {e}")
            # Modern fallback with icon
            self.logo_label.setText("🚀")
            self.logo_label.setFont(QFont("Segoe UI Emoji", 48))
            self.logo_label.setStyleSheet("""
                color: rgba(255, 255, 255, 0.8);
                background: transparent;
                padding: 20px;
            """)

    def update_text(self):
        """Update loading animation with modern timing"""
        # Smooth dot animation
        dots = '.' * ((self.dot_count % 3) + 1)
        self.loading_label.setText(f"Loading{dots}")
        self.dot_count += 1

        # Update status message
        if self.status_index < len(STATUS_MESSAGES):
            message = STATUS_MESSAGES[self.status_index]
            self.status_label.setText(message)

            # Progress through messages more smoothly
            if self.dot_count % 5 == 0:  # Every 3 seconds
                self.status_index += 1
        else:
            self.loading_label.setText("Ready")
            self.status_label.setText("Launch complete")
            self.text_timer.stop()

    def center_on_screen(self):
        """Center splash on primary screen"""
        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)

    def cleanup(self):
        """Clean up all timers and resources"""
        if hasattr(self, 'text_timer'):
            self.text_timer.stop()
        if hasattr(self, 'loading_spinner') and hasattr(self.loading_spinner, 'movie'):
            self.loading_spinner.movie.stop()

def show_splash_screen():
    """Create and display modern splash screen"""
    splash = ModernSplashScreen()
    splash.show()
    return splash

# URLs for Privacy Policy and Terms of Service
PRIVACY_POLICY_URL = "https://raw.githubusercontent.com/HarleyTG-O/sc-killfeed/main/privacy-sckt.md"
TOS_URL = "https://raw.githubusercontent.com/HarleyTG-O/sc-killfeed/main/tos-sckt.md"


def download_file(url):
    """Download a file and return its contents."""
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad status codes
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading file: {e}")
        return None

# Define the directory path for storing user acceptance data
ACCEPTANCE_FILE_PATH = os.path.join(os.getenv("LOCALAPPDATA"), "Harley's Studio", "Star Citizen Kill Tracker", "User", "acceptance_status.json")

# Ensure the directory exists
os.makedirs(os.path.dirname(ACCEPTANCE_FILE_PATH), exist_ok=True)

def save_acceptance_status(tos_accepted, privacy_accepted):
    """Save the acceptance status to a file."""
    acceptance_data = {
        "tos_accepted": tos_accepted,
        "privacy_accepted": privacy_accepted
    }

    try:
        with open(ACCEPTANCE_FILE_PATH, "w") as f:
            json.dump(acceptance_data, f)
        logging.info("Acceptance status saved successfully.")
    except Exception as e:
        logging.error(f"Failed to save acceptance status: {e}")

def load_acceptance_status():
    """Load the acceptance status from the file."""
    if os.path.exists(ACCEPTANCE_FILE_PATH):
        try:
            with open(ACCEPTANCE_FILE_PATH, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load acceptance status: {e}")
            return None
    return None

def show_tos_window(root):
    """Show the Terms of Service window."""
    # Check if the user has already accepted the Terms of Service
    acceptance_status = load_acceptance_status()
    if acceptance_status and acceptance_status.get("tos_accepted", False):
        # Skip TOS window if already accepted
        logging.info("User has already accepted the Terms of Service.")
        show_privacy_window(root)
        return

    # Download the Terms of Service content
    tos_content = download_file(TOS_URL)

    if not tos_content:
        messagebox.showerror("Error", "Failed to load Terms of Service.")
        return

    # Create a new window for the Terms of Service
    tos_win = tk.Toplevel(root)
    tos_win.title("Terms of Service")
    tos_win.configure(bg="#1a252f")
    tos_win.geometry("600x500")
    tos_win.resizable(True, True)  # Allow resizing

    # Add a scrollable frame for the text
    scroll_frame = tk.Frame(tos_win, bg="#1a252f")
    scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)

    canvas = tk.Canvas(scroll_frame, bg="#1a252f")
    canvas.pack(side="left", fill="both", expand=True)

    scrollbar = tk.Scrollbar(scroll_frame, orient="vertical", command=canvas.yview)
    scrollbar.pack(side="right", fill="y")

    canvas.configure(yscrollcommand=scrollbar.set)

    text_frame = tk.Frame(canvas, bg="#1a252f")
    canvas.create_window((0, 0), window=text_frame, anchor="nw")

    # Display Terms of Service
    tk.Label(
        text_frame,
        text="Terms of Service",
        font=("Segoe UI", 16, "bold"),
        fg="white",
        bg="#1a252f"
    ).pack(pady=(10, 5))

    tos_text = tk.Text(
        text_frame,
        wrap="word",  # Only specify once
        font=("Segoe UI", 10),
        fg="white",
        bg="#1a252f",
        bd=0,
        state=tk.NORMAL,
        relief="flat",
        undo=True
    )
    tos_text.insert(tk.END, tos_content)
    tos_text.config(state=tk.DISABLED)
    tos_text.pack(fill="both", expand=True, padx=5, pady=5)  # Fill available space dynamically

    # Accept Button for Terms of Service
    def accept_tos():
        """Close the window and proceed to the Privacy Policy."""
        tos_win.destroy()
        logging.info("User accepted the Terms of Service.")
        save_acceptance_status(tos_accepted=True, privacy_accepted=False)  # Save the acceptance status
        show_privacy_window(root)  # Show Privacy Policy after TOS is accepted

    # Add the Accept button for TOS
    accept_button = tk.Button(
        tos_win,
        text="I Accept",
        font=("Segoe UI", 12),
        fg="white",
        bg="#1a252f",
        command=accept_tos
    )
    accept_button.pack(pady=(10, 20))

    # Update the scrollable frame's region
    text_frame.update_idletasks()
    canvas.config(scrollregion=canvas.bbox("all"))

    # Center window
    tos_win.update_idletasks()
    width, height = tos_win.winfo_width(), tos_win.winfo_height()
    x = (tos_win.winfo_screenwidth() - width) // 2
    y = (tos_win.winfo_screenheight() - height) // 2
    tos_win.geometry(f"{width}x{height}+{x}+{y}")

def show_privacy_window(root):
    """Show the Privacy Policy window."""
    # Check if the user has already accepted the Privacy Policy
    acceptance_status = load_acceptance_status()
    if acceptance_status and acceptance_status.get("privacy_accepted", False):
        # Skip Privacy Policy window if already accepted
        logging.info("User has already accepted the Privacy Policy.")
        # You can proceed to start the main application here
        run_app(root)
        return

    # Download the Privacy Policy content
    privacy_content = download_file(PRIVACY_POLICY_URL)

    if not privacy_content:
        messagebox.showerror("Error", "Failed to load Privacy Policy.")
        return

    # Create a new window for the Privacy Policy
    privacy_win = tk.Toplevel(root)
    privacy_win.title("Privacy Policy")
    privacy_win.configure(bg="#1a252f")
    privacy_win.geometry("600x500")
    privacy_win.resizable(True, True)  # Allow resizing

    # Add a scrollable frame for the text
    scroll_frame = tk.Frame(privacy_win, bg="#1a252f")
    scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)

    canvas = tk.Canvas(scroll_frame, bg="#1a252f")
    canvas.pack(side="left", fill="both", expand=True)

    scrollbar = tk.Scrollbar(scroll_frame, orient="vertical", command=canvas.yview)
    scrollbar.pack(side="right", fill="y")

    canvas.configure(yscrollcommand=scrollbar.set)

    text_frame = tk.Frame(canvas, bg="#1a252f")
    canvas.create_window((0, 0), window=text_frame, anchor="nw")

    # Display Privacy Policy
    tk.Label(
        text_frame,
        text="Privacy Policy",
        font=("Segoe UI", 16, "bold"),
        fg="white",
        bg="#1a252f"
    ).pack(pady=(10, 5))

    privacy_text = tk.Text(
        text_frame,
        wrap="word",  # Only specify once
        font=("Segoe UI", 10),
        fg="white",
        bg="#1a252f",
        bd=0,
        state=tk.NORMAL,
        relief="flat",
        undo=True
    )
    privacy_text.insert(tk.END, privacy_content)
    privacy_text.config(state=tk.DISABLED)
    privacy_text.pack(fill="both", expand=True, padx=5, pady=5)  # Fill available space dynamically

    # Accept Button for Privacy Policy
    def accept_privacy():
        """Close the window and proceed to the main application."""
        privacy_win.destroy()
        logging.info("User accepted the Privacy Policy.")
        save_acceptance_status(tos_accepted=True, privacy_accepted=True)  # Save the acceptance status
        # You can proceed to start the main application here
        run_app(root)

    # Add the Accept button for Privacy Policy
    accept_button = tk.Button(
        privacy_win,
        text="I Accept",
        font=("Segoe UI", 12),
        fg="white",
        bg="#1a252f",
        command=accept_privacy
    )
    accept_button.pack(pady=(10, 20))

    # Update the scrollable frame's region
    text_frame.update_idletasks()
    canvas.config(scrollregion=canvas.bbox("all"))

    # Center window
    privacy_win.update_idletasks()
    width, height = privacy_win.winfo_width(), privacy_win.winfo_height()
    x = (privacy_win.winfo_screenwidth() - width) // 2
    y = (privacy_win.winfo_screenheight() - height) // 2
    privacy_win.geometry(f"{width}x{height}+{x}+{y}")

def is_star_citizen_running():
    """Check if StarCitizen.exe is running."""
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if 'StarCitizen.exe' in proc.info['name']:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False

# ========== Discord Setup ==========
ENABLE_DISCORD_RPC = True
DISCORD_CLIENT_ID = "1368636317671624704"
RPC = None
START_TIME = None
discord_rpc_initialized = False

if startup_flag == "disablediscordrpc":
    print("Discord RPC is disabled by startup flag.")
    ENABLE_DISCORD_RPC = False
else:
    ENABLE_DISCORD_RPC = True

# Only initialize Discord RPC if enabled
def initialize_discord_rpc():
    global RPC, START_TIME, discord_rpc_initialized

    if not ENABLE_DISCORD_RPC or discord_rpc_initialized:
        return

    try:
        RPC = Presence(DISCORD_CLIENT_ID)
        RPC.connect()
        START_TIME = int(time.time())
        discord_rpc_initialized = True
        logging.info("Discord RPC initialized successfully")

        # Initial presence update
        update_discord_presence()

        # Start the update loop
        start_presence_update_loop()

    except ImportError:
        logging.error("pypresence module not found - Discord RPC disabled")
        RPC = None
    except Exception as e:
        logging.error(f"Discord RPC init failed: {e}")
        RPC = None

def update_discord_presence():
    """Update Rich Presence with buttons and formatted display."""
    if not ENABLE_DISCORD_RPC or not RPC:
        return

    try:
        # Dynamically fetch the latest website URL from GitHub JSON
        website_json_url = "https://raw.githubusercontent.com/HarleyTG-O/sc-killfeed/main/website.json"
        website_url = None

        try:
            response = requests.get(website_json_url, timeout=5)
            if response.ok:
                data = response.json()
                if "url" in data:
                    website_url = data["url"]
        except Exception as e:
            print(f"[!] Could not fetch dynamic website URL from GitHub: {e}")

        # --- Presence Text Configuration ---
        presence_details = (
            f"🔫 SC Kill Tracker {VERSION} [{BUILD_TYPE}] [{DEPLOYMENT_SCOPE}] | "
            "© 2025 Harley's Studios | All Rights Reserved"
        )
        presence_state = f"🚀 SC Game Version: [ {game_version} ]"


        # Update Discord Rich Presence with dynamic URL
        RPC.update(
            state=presence_state,
            details=presence_details,
            large_image="logo",
            start=START_TIME,
            buttons=[
                {"label": "🌐 Join Our Discord", "url": "https://discord.gg/jxfHnGQqj7"},
                {"label": "🌐 Visit Our Website", "url": website_url}
            ]
        )
    except Exception as e:
        logging.warning(f"Couldn't update Discord presence: {e}")
        if "Connection" in str(e):
            try:
                shutdown_discord_rpc()
                initialize_discord_rpc()
            except Exception as reconnect_error:
                logging.error(f"Reconnect failed: {reconnect_error}")

def shutdown_discord_rpc():
    """Clean up Discord RPC connection"""
    global RPC, discord_rpc_initialized
    if RPC:
        try:
            RPC.clear()
            RPC.close()
        except Exception as e:
            logging.warning(f"Error shutting down RPC: {e}")
        finally:
            RPC = None
            discord_rpc_initialized = False

def start_presence_update_loop():
    """Continuously update presence every 15 seconds in a separate thread."""
    def loop():
        while ENABLE_DISCORD_RPC and discord_rpc_initialized:
            update_discord_presence()
            time.sleep(15)  # Respect Discord rate limit

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
            
# Flag to track app state and prevent reinitialization
app_initialized = False
log_monitoring_thread = None
discord_rpc_initialized = False

debug_output = None  # Initialize debug_output here

# Function to log messages to Debug Tab Text Widget
def log_to_debug(message):
    """Logs messages to the Debug tab Text widget."""
    if debug_output:
        debug_output.config(state="normal")
        debug_output.insert("end", message + "\n")
        debug_output.yview("end")  # Scroll to the end
        debug_output.config(state="disabled")

# Function to set up logging to log to the Text widget
def setup_logging():
    """Set up logging to both console and the Debug tab Text widget."""
    # Only enable debug logging if in dev mode
    if "dev" in startup_flag:
        logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    else:
        logging.basicConfig(level=logging.WARNING, format='%(message)s')
    logging.getLogger().addHandler(logging.StreamHandler())

# Show Start Dialog and log messages
def show_start_dialog_in_debug_tab(root):
    """Show the Start Dialog when the Debug tab is selected."""
    log_to_debug("Welcome to the Debug Tab!")
    log_to_debug("Star Citizen Kill Tracker is starting...")
    messagebox.showinfo("Debug Tab", "Welcome to the Debug Tab! Ready to begin testing commands.")

# --- Toast Notification Class ---
class ToastNotification(QWidget):
    closed = Signal()

    def __init__(self, title, message, duration=3000, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowStaysOnTopHint |
            Qt.FramelessWindowHint |
            Qt.Tool |
            Qt.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        # Ensure it stays on top of all windows
        self.raise_()
        self.activateWindow()

        # Use scaled size for better high-DPI support
        scaled_width, scaled_height = get_qt_scaled_size(300, 100)
        self.setFixedSize(scaled_width, scaled_height)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        header_layout = QHBoxLayout()

        # ✅ Load logo from local disk
        logo_path = get_local_logo_path()
        if logo_path.exists():
            try:
                pixmap = QPixmap(str(logo_path))
                pixmap = pixmap.scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                logo_label = QLabel()
                logo_label.setPixmap(pixmap)
                logo_label.setFixedSize(50, 50)
                header_layout.addWidget(logo_label)
                header_layout.addSpacing(10)
            except Exception as e:
                logging.error(f"Failed to load logo from local path: {e}")
        else:
            logging.warning(f"Logo file not found at {logo_path}")

        # Title with scaled font
        self.title_label = QLabel(title)
        title_font_size = get_qt_scaled_font_size(11)
        self.title_label.setFont(QFont("Segoe UI", title_font_size, QFont.Bold))
        self.title_label.setStyleSheet("color: white;")
        header_layout.addWidget(self.title_label)
        header_layout.addStretch()

        # Message with scaled font
        self.message_label = QLabel(message)
        message_font_size = get_qt_scaled_font_size(9)
        self.message_label.setFont(QFont("Segoe UI", message_font_size))
        self.message_label.setStyleSheet("color: white;")
        self.message_label.setWordWrap(True)

        # Combine layouts
        main_layout.addLayout(header_layout)
        main_layout.addWidget(self.message_label)
        main_layout.addStretch()

        # Opacity effect and animations
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)

        self.fade_in_animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_in_animation.setDuration(250)
        self.fade_in_animation.setStartValue(0.0)
        self.fade_in_animation.setEndValue(1.0)

        self.fade_out_animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_out_animation.setDuration(250)
        self.fade_out_animation.setStartValue(1.0)
        self.fade_out_animation.setEndValue(0.0)
        self.fade_out_animation.finished.connect(self._handle_close)

        self.duration = duration
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.start_fade_out)

        self.position_toast()

    def position_toast(self):
        screen = QApplication.primaryScreen()
        screen_geometry = screen.availableGeometry()  # excludes taskbar
        padding = 10
        x = screen_geometry.right() - self.width() - padding
        y = screen_geometry.bottom() - self.height() - padding
        self.move(x, y)


    def show(self):
        super().show()
        self.opacity_effect.setOpacity(0.0)
        self.fade_in_animation.start()
        self.timer.start(self.duration)

    def start_fade_out(self):
        self.fade_out_animation.start()

    def _handle_close(self):
        self.closed.emit()
        self.close()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        path = QPainterPath()
        path.addRoundedRect(self.rect(), 10, 10)
        painter.fillPath(path, QColor(45, 45, 45, 230))


# --- Notification Manager ---
class NotificationManager:
    def __init__(self):
        self.active_toasts = []

    def show_notification(self, title, message, duration=5):
        toast = ToastNotification(title, message, duration=duration * 1000)
        toast.show()
        self.active_toasts.append(toast)
        toast.closed.connect(lambda: self.on_toast_closed(toast))
        toast.show()

    def on_toast_closed(self, toast):
        self.remove_toast(toast)
        toast.deleteLater()

    def remove_toast(self, toast):
        if toast in self.active_toasts:
            self.active_toasts.remove(toast)

class DeathSignals(QObject):
    show_death = Signal(dict)


class DeathLogOverlay(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.signals = DeathSignals()
        self.dragging = False
        self.drag_position = QPoint()
        self.settings = QSettings("StarCitizenKillTracker", "Overlay")

        # Load overlay enabled state from settings (default: True)
        self._overlay_enabled = self.settings.value("overlay_enabled", True, type=bool)

        # Auto-hide system (disabled by default)
        self._auto_hide = False
        self._auto_hide_timer = QTimer()
        self._auto_hide_timer.timeout.connect(self.hide)
        self._auto_hide_timer.setSingleShot(True)

        # Color map setup
        self.color_map = {
            "No Data": QColor(100, 100, 100),  # Gray for inactive state
            "💥 Crash": QColor(142, 68, 173),
            "💥 Vehicle Crash": QColor(142, 68, 173),
            "💥 Vehicle Crash (Self)": QColor(153, 50, 204),
            "🧨 Suicide": QColor(231, 76, 60),
            "🌍 Environmental": QColor(52, 152, 219),
            "🚀 Vehicle Destruction": QColor(155, 89, 182),
            "⚔️ PvP Kill": QColor(255, 170, 0),
            "⚔️ PvP Kill (Vehicle)": QColor(255, 128, 0),
            "⚔️ PvE Kill": QColor(255, 170, 0)
        }
        
        # Setup UI & signals
        self.setup_ui()
        self.signals.show_death.connect(self._handle_death_event)
        self.show_default_content()
        self.load_settings()

        # Set initial visibility based on enabled state
        self.setVisible(self._overlay_enabled)
        if self._overlay_enabled and self._auto_hide:
            self._auto_hide_timer.start()
        else:
            self._auto_hide_timer.stop()

    def set_overlay_enabled(self, enabled: bool):
        self._overlay_enabled = enabled
        self.settings.setValue("overlay_enabled", enabled)
        self.settings.sync()

        if enabled:
            self.show()
            if self._auto_hide:
                self._auto_hide_timer.start()
            logging.info("Overlay enabled")
        else:
            self._auto_hide_timer.stop()
            self.hide()
            logging.info("Overlay disabled")

    def is_overlay_enabled(self) -> bool:
        return self._overlay_enabled

    def set_auto_hide(self, active: bool):
        self._auto_hide = active
        if active:
            self._auto_hide_timer.start(10000)  # example 10 seconds
        else:
            self._auto_hide_timer.stop()


    def is_overlay_enabled(self):
        return self._overlay_enabled
    
    def set_auto_hide(self, active: bool):
        """Enable or disable the auto-hide mechanism"""
        self._auto_hide = active
        if active:
            self._auto_hide_timer.start(10000)  # 10 seconds
        else:
            self._auto_hide_timer.stop()
            
    def setup_ui(self):
        # Window setup with scaled size for better high-DPI support
        self.setWindowFlags(
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnTopHint |
            Qt.Tool |
            Qt.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        # Ensure overlay stays on top
        self.raise_()
        self.activateWindow()

        # Use scaled overlay size with resizing capability
        scaled_width, scaled_height = get_qt_scaled_size(435, 245)
        self.setMinimumSize(int(scaled_width * 0.7), int(scaled_height * 0.7))  # Allow smaller
        self.setMaximumSize(int(scaled_width * 2.0), int(scaled_height * 2.0))  # Allow larger
        self.resize(scaled_width, scaled_height)  # Set default size

        # Enable resizing for frameless window
        self.setMouseTracking(True)
        self.resize_border = 10  # Border width for resize detection

        # Add resize grip for corner resizing
        try:
            self.resize_grip = QSizeGrip(self)
            self.resize_grip.setStyleSheet("""
                QSizeGrip {
                    background-color: rgba(100, 100, 100, 150);
                    width: 16px;
                    height: 16px;
                    border: 1px solid rgba(150, 150, 150, 100);
                }
            """)
            self.resize_grip.setFixedSize(16, 16)
            self.resize_grip.show()
        except Exception as e:
            logging.warning(f"Failed to create resize grip: {e}")
            # Create a simple placeholder if QSizeGrip fails
            self.resize_grip = QLabel("⟲")
            self.resize_grip.setFixedSize(16, 16)
            self.resize_grip.setStyleSheet("color: #888; font-size: 12px;")
            self.resize_grip.setAlignment(Qt.AlignCenter)
        
        # Main container
        self.container = QFrame()
        self.container.setStyleSheet("""
            QFrame {
                background-color: rgba(30, 30, 30, 220);
                border-radius: 8px;
                border: 1px solid #444;
            }
        """)
        
        # Main layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.addWidget(self.container)
        
        # Container layout
        self.container_layout = QVBoxLayout(self.container)
        self.container_layout.setContentsMargins(10, 10, 10, 10)
        self.container_layout.setSpacing(5)
        
        # Title bar with settings
        self.setup_title_bar()
        
        # Settings panel
        self.setup_settings_panel()
        
        # Content area
        self.setup_content_area()
        
        # Initial setup
        self.show()
        
    def setup_title_bar(self):
        self.title_bar = QWidget()
        self.title_bar.setStyleSheet("""
            background-color: rgba(45, 45, 45, 200); 
            border-radius: 5px;
        """)
        
        title_layout = QHBoxLayout(self.title_bar)
        title_layout.setContentsMargins(8, 5, 8, 5)
        
        self.title_label = QLabel("Star Citizen Kill Tracker")
        title_font_size = get_qt_scaled_font_size(12)
        self.title_label.setStyleSheet(f"""
            color: white;
            font-weight: bold;
            font-size: {title_font_size}px;
        """)
        
        self.settings_btn = QPushButton("⚙️")
        self.settings_btn.setFixedSize(20, 20)
        self.settings_btn.setStyleSheet("""
            QPushButton {
                color: white;
                border: none;
                font-size: 14px;
            }
            QPushButton:hover {
                color: #3498db;
            }
        """)
        self.settings_btn.clicked.connect(self.toggle_settings)
        
        self.close_btn = QPushButton("×")
        self.close_btn.setFixedSize(20, 20)
        self.close_btn.setStyleSheet("""
            QPushButton {
                color: white;
                border: none;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                color: red;
            }
        """)
        self.close_btn.clicked.connect(self.hide)
        
        title_layout.addWidget(self.title_label)
        title_layout.addItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        title_layout.addWidget(self.settings_btn)
        title_layout.addWidget(self.close_btn)
        
        self.container_layout.addWidget(self.title_bar)
    
    def setup_settings_panel(self):
        self.settings_panel = QWidget()
        self.settings_panel.setStyleSheet("""
            background-color: rgba(50, 50, 50, 200); 
            border-radius: 5px;
            padding: 5px;
        """)
        
        self.settings_layout = QVBoxLayout(self.settings_panel)
        self.settings_layout.setContentsMargins(5, 5, 5, 5)
        
        # Auto-hide checkbox (disabled by default)
        self.auto_hide_checkbox = QCheckBox("Auto Hide (10 seconds)")
        self.auto_hide_checkbox.setStyleSheet("color: white;")
        self.auto_hide_checkbox.stateChanged.connect(self.toggle_auto_hide)
        
        self.settings_layout.addWidget(self.auto_hide_checkbox)
        self.settings_panel.hide()
        
        self.container_layout.addWidget(self.settings_panel)
    
    def setup_content_area(self):
        self.content = QWidget()
        self.content.setStyleSheet("background-color: transparent;")
        
        self.message_layout = QVBoxLayout(self.content)
        self.message_layout.setContentsMargins(5, 5, 5, 5)
        self.message_layout.setSpacing(8)
        
        # Kill type indicator
        self.kill_type_bar = QWidget()
        self.kill_type_bar.setFixedHeight(4)
        self.kill_type_bar.setStyleSheet("""
            background-color: #AAAAAA; 
            border-radius: 2px;
        """)
        
        # Message fields with scaled fonts
        time_font_size = get_qt_scaled_font_size(10)
        title_font_size = get_qt_scaled_font_size(12)
        content_font_size = get_qt_scaled_font_size(11)
        footer_font_size = get_qt_scaled_font_size(9)

        self.time_label = QLabel()
        self.time_label.setStyleSheet(f"""
            color: #AAAAAA;
            font-size: {time_font_size}px;
        """)

        self.event_title_label = QLabel()
        self.event_title_label.setStyleSheet(f"""
            color: white;
            font-weight: bold;
            font-size: {title_font_size}px;
        """)

        self.zone_label = QLabel()
        self.zone_label.setStyleSheet(f"""
            color: #DDD;
            font-size: {content_font_size}px;
        """)

        self.combatants_label = QLabel()
        self.combatants_label.setStyleSheet(f"""
            color: white;
            font-size: {content_font_size}px;
        """)

        self.details_label = QLabel()
        self.details_label.setStyleSheet(f"""
            color: #DDD;
            font-size: {content_font_size}px;
        """)

        self.footer_label = QLabel()
        self.footer_label.setStyleSheet(f"""
            color: #777;
            font-size: {footer_font_size}px;
        """)
        
        # Add to layout
        self.message_layout.addWidget(self.kill_type_bar)
        self.message_layout.addWidget(self.time_label)
        self.message_layout.addWidget(self.event_title_label)
        self.message_layout.addWidget(self.zone_label)
        self.message_layout.addWidget(self.combatants_label)
        self.message_layout.addWidget(self.details_label)
        self.message_layout.addSpacerItem(QSpacerItem(10, 10, QSizePolicy.Minimum, QSizePolicy.Expanding))
        self.message_layout.addWidget(self.footer_label)

        # Create a bottom layout with footer and resize grip
        bottom_widget = QWidget()
        bottom_layout = QHBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(5)

        # Add footer label and stretch, then resize grip
        bottom_layout.addWidget(self.footer_label)
        bottom_layout.addStretch()
        bottom_layout.addWidget(self.resize_grip)

        # Replace the footer label with the bottom widget
        self.message_layout.removeWidget(self.footer_label)
        self.message_layout.addWidget(bottom_widget)

        self.container_layout.addWidget(self.content)
    
    def show_default_content(self):
        """Show default 'No Data' state in the overlay UI"""
        # Set neutral gray color for inactive state
        self.kill_type_bar.setStyleSheet("""
            background-color: #646464;
            border-radius: 2px;
        """)
        
        current_time = datetime.now().strftime("%H:%M:%S")
        self.time_label.setText(f"🕒 {current_time} - Awaiting Data")
        self.event_title_label.setText("Awaiting Data")
        self.zone_label.setText("🌌 <b>Zone:</b> Awaiting Data")
        self.combatants_label.setText(
            "🧍 <b>Victim:</b> Awaiting Data\n"
            "🗡️ <b>Killer:</b> Awaiting Data"
        )
        self.details_label.setText(
            "🔫 <b>Weapon:</b> Awaiting Data\n"
            "☠️ <b>Damage Type:</b> Awaiting Data"
        )
        self.footer_label.setText(f"Star Citizen Kill Tracker -{VERSION}-{BUILD_TYPE}({DEPLOYMENT_SCOPE}")
        
        self.show()
        self.adjustSize()

        
    def toggle_settings(self):
        self.settings_panel.setVisible(not self.settings_panel.isVisible())
        self.adjustSize()
        
    def toggle_auto_hide(self, state):
        enabled = bool(state)
        self.settings.setValue("auto_hide", enabled)
        self.set_auto_hide(enabled)
        
    def load_settings(self):
        pos = self.settings.value("window_pos", QPoint(100, 100))
        self.move(pos)
        # Auto-hide is disabled by default
        auto_hide = self.settings.value("auto_hide", False, type=bool)
        self.auto_hide_checkbox.setChecked(auto_hide)
        self.set_auto_hide(auto_hide)
        
    def closeEvent(self, event):
        self.settings.setValue("window_pos", self.pos())
        event.accept()

    def show_death_log(self, data: dict, kill_type: str = "No Data"):
        self.signals.show_death.emit({
            "data": data,
            "kill_type": kill_type
        })

    def _handle_death_event(self, payload):
        """Handle incoming death events"""
        data = payload["data"]
        kill_type = payload.get("kill_type") or data.get("kill_type", "No Data")

        color = self.color_map.get(kill_type, QColor(170, 170, 170))
        self.kill_type_bar.setStyleSheet(f"""
            background-color: {color.name()};
            border-radius: 2px;
        """)
        
        # Format time
        time_text = f"🕒 {data['timestamp']}"
        if data.get('discord_timestamp'):
            time_text += f" - {data['discord_timestamp']}"
        
        # Format title
        title_map = {
            "💥 Vehicle Crash": "🚗 Vehicle Accident",
            "💥 Vehicle Crash (Self)": "🚗 Vehicle Crash",
            "🧨 Suicide": "🧨 Suicide Event",
            "💥 Crash": "💥 Crash Event",
            "🌍 Environmental": "🌍 Environmental Hazard"
        }
        title = title_map.get(kill_type, kill_type)
        
        # Format combatants
        if kill_type and kill_type.endswith("(Self)"):
            combatants = f"🧍 <b>Player:</b> {data.get('victim', 'Unknown')} (ID: {data.get('victim_id', '?')})"
        else:
            combatants = (
                f"🧍 <b>Victim:</b> {data.get('victim', 'Unknown')} (ID: {data.get('victim_id', '?')})\n"
                f"🗡️ <b>Killer:</b> {data.get('killer', 'Unknown')} (ID: {data.get('killer_id', '?')})"
            )
        
        # Format details
        if kill_type in ["🧨 Suicide", "💥 Crash", "💥 Vehicle Crash", "💥 Vehicle Crash (Self)"]:
            details = f"💀 <b>Method:</b> {data.get('weapon', 'Unknown')}"
        else:
            details = (
                f"🔫 <b>Weapon:</b> {data.get('weapon', 'Unknown')}\n"
                f"☠️ <b>Damage Type:</b> {data.get('damage_type', 'Unknown')}"
            )
        
        # Update labels
        self.time_label.setText(time_text)
        self.event_title_label.setText(kill_type)
        self.zone_label.setText(f"🌌 <b>Zone:</b> {data.get('zone', 'Unknown Location')}")
        self.combatants_label.setText(combatants)
        self.details_label.setText(details)
        self.footer_label.setText(f"Star Citizen Kill Tracker System [Version info : {VERSION}-{BUILD_TYPE}({DEPLOYMENT_SCOPE})]")
        
        self.adjustSize()
        self.show()
        
        if self._auto_hide:
            self._auto_hide_timer.start(10000)   
        
    def _show_death_log(self, payload):
        """Main thread implementation for updating the death log overlay."""
        data = payload.get("data", {})
        kill_type = payload["kill_type"]

        # Update color bar
        color = self.color_map.get(kill_type, QColor(170, 170, 170))
        self.kill_type_bar.setStyleSheet(f"""
            background-color: {color.name()};
            border-radius: 2px;
        """)

        # Format time
        time_text = f"🕒 {data.get('timestamp', 'Unknown')}"
        if data.get('discord_timestamp'):
            time_text += f" - {data['discord_timestamp']}"

        # Format event title
        title_map = {
            "💥 Vehicle Crash": "🚗 Vehicle Accident",
            "💥 Vehicle Crash (Self)": "🚗 Vehicle Crash",
            "🧨 Suicide": "🧨 Suicide Event",
            "💥 Crash": "💥 Crash Event",
            "🌍 Environmental": "🌍 Environmental Hazard"
        }
        title = title_map.get(kill_type, kill_type)

        # Format combatants
        if kill_type.endswith("(Self)"):
            combatants = f"🧍 <b>Player:</b> {data.get('victim', 'Unknown')} (ID: {data.get('victim_id', '?')})"
        else:
            combatants = (
                f"🧍 <b>Victim:</b> {data.get('victim', 'Unknown')} (ID: {data.get('victim_id', '?')})\n"
                f"🗡️ <b>Killer:</b> {data.get('killer', 'Unknown')} (ID: {data.get('killer_id', '?')})"
            )

        # Format details
        if kill_type in {"🧨 Suicide", "💥 Crash", "💥 Vehicle Crash", "💥 Vehicle Crash (Self)"}:
            details = f"💀 <b>Method:</b> {data.get('weapon', 'Unknown')}"
        else:
            details = (
                f"🔫 <b>Weapon:</b> {data.get('weapon', 'Unknown')}\n"
                f"☠️ <b>Damage Type:</b> {data.get('damage_type', 'Unknown')}"
            )

        # Update overlay labels
        self.time_label.setText(time_text)
        self.event_title_label.setText(kill_type)
        self.zone_label.setText(f"🌌 <b>Zone:</b> {data.get('zone', 'Unknown Location')}")
        self.combatants_label.setText(combatants)
        self.details_label.setText(details)
        self.footer_label.setText(
            f"Star Citizen Kill Tracker System [Version info : {VERSION}-{BUILD_TYPE}({DEPLOYMENT_SCOPE})]"
        )

        self.adjustSize()
        self.show()

        if self._auto_hide:
            self._auto_hide_timer.start(10000)  # Hide after 10 seconds if auto-hide is enabled

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            # Check if we're near the resize grip area (bottom-right corner)
            pos = event.position().toPoint()
            if (pos.x() > self.width() - self.resize_border and
                pos.y() > self.height() - self.resize_border):
                self.resizing = True
                self.resize_start_pos = event.globalPosition().toPoint()
                self.resize_start_size = self.size()
            else:
                self.dragging = True
                self.drag_position = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        pos = event.position().toPoint()

        # Change cursor when near resize area
        if (pos.x() > self.width() - self.resize_border and
            pos.y() > self.height() - self.resize_border):
            self.setCursor(Qt.SizeFDiagCursor)
        else:
            self.setCursor(Qt.ArrowCursor)

        if hasattr(self, 'resizing') and self.resizing and event.buttons() & Qt.MouseButton.LeftButton:
            # Handle resizing
            global_pos = event.globalPosition().toPoint()
            diff = global_pos - self.resize_start_pos
            new_size = self.resize_start_size + QSize(diff.x(), diff.y())

            # Apply size constraints
            new_size = new_size.expandedTo(self.minimumSize())
            new_size = new_size.boundedTo(self.maximumSize())

            self.resize(new_size)
            event.accept()
        elif self.dragging and event.buttons() & Qt.MouseButton.LeftButton:
            # Handle dragging
            self.move(event.globalPosition().toPoint() - self.drag_position)
            event.accept()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.dragging = False
            if hasattr(self, 'resizing'):
                self.resizing = False
            self.setCursor(Qt.ArrowCursor)
            event.accept()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(30, 30, 30, 240))  # Slight opacity to see window
        painter.drawRoundedRect(self.rect(), 10, 10)

missing_start_time = None  # global or outer scope
qt_app = None
manager = None

# --- Overlay flag logic (OUTSIDE the class) ---
if startup_flag == "disableoverlay":
    print("Overlay is disabled by startup flag.")
    OVERLAY_ENABLED = False
else:
    OVERLAY_ENABLED = True

death_overlay = None
if OVERLAY_ENABLED:
    death_overlay = DeathLogOverlay

def is_star_citizen_running() -> bool:
    """
    Returns True if any StarCitizen.exe process is running (LIVE or PTU), else False.
    """
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == "starcitizen.exe":
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False

def handle_flags_and_exit(flags, root):
    """Handle flags and return True if application should exit"""
    if flags["disable_client"]:
        messagebox.showinfo("Client Disabled", "Star Citizen Kill Tracker - Client Disabled.")
        root.quit()
        return True

    if flags["mandatory_update"]:
        messagebox.showerror(
            "Update Required",
            f"This version ({VERSION}) is outdated.\nPlease update to {flags['required_version']}."
        )
        root.quit()
        return True
        
    return False  # Continue execution

def launch_after_tos(root, splash=None):
    """
    Handle TOS/Privacy flow and launch main app.
    Splash is an optional reference to destroy before proceeding.
    """
    # Check acceptance status first
    acceptance_status = load_acceptance_status()

    if splash and splash.winfo_exists():
        splash.destroy()

    if acceptance_status and acceptance_status.get("tos_accepted", False):
        if acceptance_status.get("privacy_accepted", False):
            run_app(root)
        else:
            show_privacy_window(root)
    else:
        show_tos_window(root)


import subprocess

result = subprocess.run(
    ["powershell", "-Command", "Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name"],
    capture_output=True, text=True
)
print(result.stdout.strip())

def start_version_monitor():
    monitor_thread = threading.Thread(target=monitor_version_updates, daemon=True)
    monitor_thread.start()

def load_first_user_data(key: bytes) -> dict | None:
    """Load and decrypt the first user ID file found in USER_DIR."""
    import glob
    user_files = glob.glob(os.path.join(USER_DIR, "*_id.enc"))
    if not user_files:
        return None
    user_file = user_files[0]
    try:
        with open(user_file, "rb") as f:
            encrypted = f.read()
        return decrypt_data(encrypted, key)
    except Exception as e:
        logging.error(f"Failed to load user ID file: {e}")
        return None
    

def run_app(root):
    global app_initialized, log_monitoring_thread, discord_rpc_initialized, qt_app, death_overlay, running

    if app_initialized:
        logging.info("Application already running. Skipping initialization.")
        return

    try:
        # Initialize QApplication once in the main thread
        if qt_app is None:
            qt_app = QApplication(sys.argv)

        # Now safe to create any Qt widgets
        death_overlay = DeathLogOverlay()


        # Start your log monitoring thread (no change here)
        if log_monitoring_thread is None or not log_monitoring_thread.is_alive():
            log_monitoring_thread = threading.Thread(
                target=monitor_log,
                args=(death_overlay,),
                daemon=True
            )
            log_monitoring_thread.start()

        # Start tray icon thread
        threading.Thread(target=lambda: tray_icon(root), daemon=True).start()

        # Load logo
        logo_path = get_local_logo_path()
        if not logo_path or not os.path.exists(logo_path):
            raise FileNotFoundError(f"Logo file not found: {logo_path}")

        icon_img = Image.open(logo_path).convert("RGBA")
        icon_img.thumbnail((64, 64), Image.LANCZOS)
        root.iconphoto(True, ImageTk.PhotoImage(icon_img))

        # Initialize Discord RPC only once
        if not discord_rpc_initialized:
            initialize_discord_rpc()
            discord_rpc_initialized = True

        def check_loop():
            """Main monitoring loop with proper shutdown handling"""
            global missing_start_time
            
            if not running:
                root.destroy()
                return
                
            if not is_star_citizen_running():
                if missing_start_time is None:
                    missing_start_time = time.time()
                elif time.time() - missing_start_time >= 30:
                    messagebox.showwarning(
                        "Star Citizen Not Running",
                        "Star Citizen has not been running for 30 seconds. Closing application."
                    )
                    root.quit()
                    return
            else:
                missing_start_time = None
                update_discord_presence()
            
            # Schedule next check based on current state
            delay = 1000 if missing_start_time else 3000
            root.after(delay, check_loop)

        # Mark app as initialized
        app_initialized = True

    except Exception as e:
        logging.error(f"Error in run_app: {e}")
        sys.exit(1)

def main():
    global manager, qt_app, root

    try:
        # Create splash screen (Qt widget)
        splash = ModernSplashScreen()
        splash.show()

        def after_splash():
            global manager, qt_app

            # Destroy splash if it exists
            if splash and splash.isVisible():
                splash.close()

            # Initialize QApplication (must be before any Qt widgets)
            if qt_app is None:
                qt_app = QApplication(sys.argv)

            # Initialize NotificationManager AFTER QApplication
            manager = NotificationManager()
            manager.show_notification(
                "Star Citizen Kill Tracker",
                "Has Successfully Started",
                duration=15
            )

            # Launch app logic (TOS check → run_app)
            launch_after_tos(root)

        # Schedule after_splash to run after SPLASH_TIMEOUT ms
        QTimer.singleShot(SPLASH_TIMEOUT, after_splash)

        # Start the Tkinter event loop (if needed)
        root.mainloop()

    except Exception as e:
        logging.error(f"Fatal error in main: {e}", exc_info=True)
        if qt_app:
            qt_app.quit()
        sys.exit(1)

def override_ui_for_guest_mode():
    """
    Override all user info UI elements for guest mode.
    Call this after setting globals()["user_data"] = user_data for guest.
    """
    # Example: If you have a main menu open, refresh the user info section
    # You may need to pass or track a reference to your main menu window/frame
    try:
        # If you use a global or accessible reference to your main menu window/frame:
        # For example, if you have a global main_menu_win or similar:
        #   add_user_info_section(main_menu_win.user_info_card)
        # Or, if you use a function to show the main menu, you can call it again:
        #   show_main_menu(root)
        # Or, if you have a user info frame, destroy and recreate it:
        #   for widget in user_info_card.winfo_children():
        #       widget.destroy()
        #   add_user_info_section(user_info_card)
        # The actual implementation depends on your UI structure.

        # Example for Tkinter: force refresh if main menu is open
        # (Assuming you have a reference to the user info card/frame)
        if "user_info_card" in globals():
            user_info_card = globals()["user_info_card"]
            for widget in user_info_card.winfo_children():
                widget.destroy()
            add_user_info_section(user_info_card)
    except Exception as e:
        logging.error(f"Failed to override UI for guest mode: {e}")

if __name__ == "__main__":
    startup_flag = get_startup_flag()

    # --- Startup Flags ---
    if "fastload" in startup_flag:
        SPLASH_TIMEOUT = 1000
        print("Fastload mode enabled: Splash timeout reduced.")

    if "dev" in startup_flag:
        logging.getLogger().setLevel(logging.DEBUG)
        print("Developer mode enabled: Debug logging on.")
    else:
        # Set logging to WARNING level for normal users to reduce console spam
        logging.getLogger().setLevel(logging.WARNING)

    qt_app = QApplication.instance() or QApplication(sys.argv)
    qt_app.setQuitOnLastWindowClosed(False)

    sys.excepthook = handle_crash

    try:
        USER_LANGUAGE = load_user_language()

        # Create hidden Tk root for dialogs; do NOT run mainloop here
        root = tk.Tk()
        root.withdraw()

        download_logo_if_needed()

        elevated = "--elevated" in sys.argv

        if not elevated:
            # --- Always show welcome screen ---
            result = show_welcome_screen()  # Qt dialog
            if result != QDialog.Accepted:
                qt_app.quit()
                sys.exit(0)

            if startup_flag == "guest":
                # Set up guest user_data and skip registration dialogs
                key = load_encryption_key()
                user_data = {
                    "Username": "Guest",
                    "SCKillTrac ID": "guest@SCKillTrac",
                    "UUID": f"guest-SCKillTrac-{uuid.uuid4()}"
                }
                # Override global user_data for guest mode
                globals()["user_data"] = user_data
                override_ui_for_guest_mode()
            else:
                # Try KeyAuth authentication first
                keyauth_initialized = False
                if KEYAUTH_AVAILABLE:
                    keyauth_initialized = initialize_keyauth_system()

                if keyauth_initialized:
                    # Use KeyAuth authentication
                    auth_success, user_data = authenticate_with_keyauth()
                    if not auth_success:
                        qt_app.quit()
                        sys.exit(0)

                    # Send KeyAuth user registration/login webhook
                    if user_data:
                        send_user_registration_webhook(user_data, login=True, keyauth=True)

                    # Start KeyAuth session monitoring
                    start_keyauth_session_monitoring()
                else:
                    # Fallback to local authentication system
                    logging.info("Using local authentication system")
                    if not user_registered():
                        registration_dialog = RegistrationDialog()  # Qt dialog
                        if registration_dialog.exec() != QDialog.Accepted:
                            qt_app.quit()
                            sys.exit(0)

                        key = load_encryption_key()
                        user_data = load_first_user_data(key)
                        if user_data:
                            send_user_registration_webhook(user_data)
                    else:
                        key = load_encryption_key()
                        user_data = load_first_user_data(key)
                        if user_data:
                            send_user_registration_webhook(user_data, login=True)

        if not is_user_admin():
            if not run_as_admin(extra_args=["--elevated"]):
                sys.exit(0)
            sys.exit(0)

        create_shortcut()
        start_version_monitor()

        # If you need to show Tkinter dialogs here, do it synchronously without mainloop:
        # For example, TOS acceptance (pseudo-code)
        acceptance_status = load_acceptance_status()
        if not acceptance_status or not acceptance_status.get("tos_accepted", False):
            show_tos_window(root)  # Tkinter dialog, blocks until closed
        elif not acceptance_status.get("privacy_accepted", False):
            show_privacy_window(root)  # Tkinter dialog, blocks until closed

        # Run main logic (Qt splash screen and app)
        main()

        # Now start Qt event loop (only one event loop)
        sys.exit(qt_app.exec())

    except KeyboardInterrupt:
        logging.info("Application closed by user")
        sys.exit(0)
    except Exception as e:
        logging.critical(f"Fatal initialization error: {e}", exc_info=True)
        QMessageBox.critical(None, "Fatal Error", f"An error occurred:\n{e}")
        sys.exit(1)