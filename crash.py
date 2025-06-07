import os
import json
import logging
import traceback
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
import sys
import requests
import re
import hashlib
from datetime import datetime, timedelta
import platform
import io
import threading
import queue
import subprocess
import sqlite3
from pathlib import Path
import time
import uuid
import tempfile
import zipfile

# Optional imports with fallbacks
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Warning: PIL not available, some image features may not work")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not available, system monitoring features limited")

try:
    import winreg
    import ctypes
    from ctypes import wintypes
    WINDOWS_FEATURES_AVAILABLE = True
except ImportError:
    WINDOWS_FEATURES_AVAILABLE = False
    print("Warning: Windows-specific features not available")

try:
    import asyncio
    import aiohttp
    ASYNC_FEATURES_AVAILABLE = True
except ImportError:
    ASYNC_FEATURES_AVAILABLE = False
    print("Warning: Async features not available")

# === CONFIG ===
LOGO_URL = "https://raw.githubusercontent.com/HarleyTG-O/sc-killfeed/main/logo.png"
CRASH_REPORT_WEBHOOK_URL = "https://discord.com/api/webhooks/1367288629260714135/hCUg3D1g-FwE_CqlI0LXqpj4W4jnK4qZ6RQ53tvTmz0Gzuwp7sQPTJUVyV2VYH8bRH1N"
GAME_LOG_FILE = "Game.log"  # Default path to Game.log (can be overridden)

# === ERROR CODES FOR SCKILLTRACK ===
ERROR_CODES = {
    # General Application Errors (1000-1999)
    1000: "GENERAL_APPLICATION_ERROR",
    1001: "INITIALIZATION_FAILED",
    1002: "CONFIGURATION_ERROR",
    1003: "PERMISSION_DENIED",
    1004: "RESOURCE_NOT_FOUND",
    1005: "MEMORY_ERROR",
    1006: "THREAD_ERROR",
    1007: "GUI_ERROR",
    1008: "FONT_INSTALLATION_ERROR",
    1009: "LOGO_LOAD_ERROR",

    # File System Errors (2000-2999)
    2000: "FILE_SYSTEM_ERROR",
    2001: "LOG_FILE_NOT_FOUND",
    2002: "LOG_FILE_ACCESS_DENIED",
    2003: "LOG_FILE_CORRUPTED",
    2004: "CONFIG_FILE_ERROR",
    2005: "USER_DATA_FILE_ERROR",
    2006: "LAUNCHER_STORE_ERROR",
    2007: "MANIFEST_FILE_ERROR",
    2008: "ENCRYPTION_KEY_ERROR",
    2009: "FILE_WRITE_ERROR",

    # Network/API Errors (3000-3999)
    3000: "NETWORK_ERROR",
    3001: "DISCORD_WEBHOOK_FAILED",
    3002: "API_CONNECTION_FAILED",
    3003: "STARCITIZEN_API_ERROR",
    3004: "REMOTE_CONFIG_FETCH_FAILED",
    3005: "UPDATE_CHECK_FAILED",
    3006: "LOGO_DOWNLOAD_FAILED",
    3007: "FONT_DOWNLOAD_FAILED",
    3008: "TIMEOUT_ERROR",
    3009: "SSL_ERROR",

    # Game Integration Errors (4000-4999)
    4000: "GAME_INTEGRATION_ERROR",
    4001: "GAME_LOG_MONITOR_FAILED",
    4002: "DEATH_EVENT_PARSE_ERROR",
    4003: "GAME_VERSION_DETECTION_FAILED",
    4004: "STARCITIZEN_PROCESS_NOT_FOUND",
    4005: "GAME_LOG_TAIL_ERROR",
    4006: "REGEX_PATTERN_ERROR",
    4007: "KILL_CLASSIFICATION_ERROR",
    4008: "OVERLAY_DISPLAY_ERROR",
    4009: "DISCORD_RPC_ERROR",

    # User Authentication Errors (5000-5999)
    5000: "USER_AUTH_ERROR",
    5001: "USER_REGISTRATION_FAILED",
    5002: "USER_LOGIN_FAILED",
    5003: "USER_DATA_ENCRYPTION_FAILED",
    5004: "USER_DATA_DECRYPTION_FAILED",
    5005: "USER_PROFILE_CORRUPTED",
    5006: "USER_SETTINGS_ERROR",
    5007: "LANGUAGE_SETTING_ERROR",
    5008: "USER_ID_GENERATION_FAILED",
    5009: "USER_WEBHOOK_FAILED",

    # UI/Display Errors (6000-6999)
    6000: "UI_ERROR",
    6001: "OVERLAY_CREATION_FAILED",
    6002: "MAIN_WINDOW_ERROR",
    6003: "DIALOG_CREATION_FAILED",
    6004: "SCALING_CALCULATION_ERROR",
    6005: "THEME_APPLICATION_ERROR",
    6006: "WIDGET_CREATION_ERROR",
    6007: "EVENT_HANDLER_ERROR",
    6008: "RESIZE_HANDLER_ERROR",
    6009: "ANIMATION_ERROR",

    # System Integration Errors (7000-7999)
    7000: "SYSTEM_INTEGRATION_ERROR",
    7001: "ADMIN_ELEVATION_FAILED",
    7002: "REGISTRY_ACCESS_ERROR",
    7003: "PROCESS_MONITORING_ERROR",
    7004: "SYSTEM_TRAY_ERROR",
    7005: "SHORTCUT_CREATION_ERROR",
    7006: "DPI_AWARENESS_ERROR",
    7007: "WINDOWS_API_ERROR",
    7008: "PSUTIL_ERROR",
    7009: "WINREG_ERROR",

    # Crash/Vehicle Related Errors (8000-8999)
    8000: "CRASH_DETECTION_ERROR",
    8001: "VEHICLE_CRASH_CLASSIFICATION_ERROR",
    8002: "CRASH_REPORT_GENERATION_FAILED",
    8003: "CRASH_DATA_CORRUPTION",
    8004: "CRASH_WEBHOOK_FAILED",
    8005: "CRASH_LOG_WRITE_ERROR",
    8006: "CRASH_DIALOG_ERROR",
    8007: "CRASH_RECOVERY_FAILED",
    8008: "CRASH_DEDUPLICATION_ERROR",
    8009: "CRASH_ANALYSIS_ERROR",
}

# Get proper local appdata paths
LOCAL_APPDATA = os.getenv('LOCALAPPDATA')
APP_DATA_DIR = os.path.join(LOCAL_APPDATA, "Harley's Studio", "Star Citizen Kill Tracker")
CRASH_LOG_DIR = os.path.join(APP_DATA_DIR, "Crash Handler", "Logs")
CONFIG_DIR = os.path.join(APP_DATA_DIR, "Config")

# Ensure directories exist
os.makedirs(CRASH_LOG_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

CRASH_COOLDOWN_MINUTES = 5  # Minutes to wait before reporting duplicate crashes

# Visual configuration - modern dark theme
BACKGROUND_COLOR = "#15202b"  # Darker blue background
HEADER_COLOR = "#192734"      # Slightly lighter blue for headers
TEXT_COLOR = "#ffffff"        # White text
ERROR_COLOR = "#ff5555"       # Red for error messages
BUTTON_BG = "#1da1f2"         # Blue for buttons
BUTTON_FG = "#ffffff"         # White text for buttons
BUTTON_HOVER_BG = "#0c85d0"   # Darker blue for button hover
BUTTON_DENY_BG = "#db4437"    # Red for deny button
BUTTON_DENY_HOVER_BG = "#b33228"  # Darker red for deny button hover
BUTTON_NEUTRAL_BG = "#657786" # Neutral gray button
BUTTON_NEUTRAL_HOVER_BG = "#4d5c6b" # Darker gray button hover
TEXT_AREA_BG = "#192734"      # Slightly lighter blue for text areas
BORDER_COLOR = "#38444d"      # Border color

# Responsive UI configuration
MIN_WINDOW_WIDTH = 500
MIN_WINDOW_HEIGHT = 400
DEFAULT_WINDOW_WIDTH = 700
DEFAULT_WINDOW_HEIGHT = 600
PADDING_SMALL = 5
PADDING_MEDIUM = 10
PADDING_LARGE = 20

# Fonts with dynamic sizing based on screen resolution
def get_font_sizes():
    """Get appropriate font sizes based on screen resolution."""
    try:
        # Get screen metrics
        root = tk.Tk()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        root.destroy()
        
        # Calculate scaling factor (basic approach)
        # For high-res screens (4K+)
        if screen_width >= 3840 or screen_height >= 2160:
            return {
                "header_large": 22,
                "header": 16, 
                "subheader": 14,
                "normal": 12,
                "small": 10,
                "code": 11
            }
        # For higher-res screens (1440p)
        elif screen_width >= 2560 or screen_height >= 1440:
            return {
                "header_large": 20,
                "header": 14, 
                "subheader": 12,
                "normal": 11,
                "small": 10,
                "code": 10
            }
        # For standard screens (1080p and below)
        else:
            return {
                "header_large": 18,
                "header": 12, 
                "subheader": 11,
                "normal": 10,
                "small": 9,
                "code": 9
            }
    except Exception:
        # Fallback sizes if there's an error
        return {
            "header_large": 18,
            "header": 12, 
            "subheader": 11,
            "normal": 10,
            "small": 9,
            "code": 9
        }

# Get font sizes based on screen resolution
FONT_SIZES = get_font_sizes()

# Fonts
FONT_FAMILY = "Segoe UI" if platform.system() == "Windows" else "Helvetica"
CODE_FONT_FAMILY = "Consolas" if platform.system() == "Windows" else "Courier"

# Dynamic font configurations
HEADER_LARGE_FONT = (FONT_FAMILY, FONT_SIZES["header_large"], "bold")
HEADER_FONT = (FONT_FAMILY, FONT_SIZES["header"], "bold")
SUBHEADER_FONT = (FONT_FAMILY, FONT_SIZES["subheader"])
NORMAL_FONT = (FONT_FAMILY, FONT_SIZES["normal"])
SMALL_FONT = (FONT_FAMILY, FONT_SIZES["small"])
BUTTON_FONT = (FONT_FAMILY, FONT_SIZES["normal"])
CODE_FONT = (CODE_FONT_FAMILY, FONT_SIZES["code"])

# Advanced crash tracking
LAST_CRASH_TIME = None
LAST_CRASH_HASH = None
CRASH_DATABASE_PATH = os.path.join(CRASH_LOG_DIR, "crash_database.db")
CRASH_ANALYTICS_ENABLED = True
CRASH_REPORT_QUEUE = queue.Queue()
DIAGNOSTIC_THREAD = None
CRASH_COUNTER = 0
SESSION_ID = str(uuid.uuid4())

# Advanced configuration
ADVANCED_DIAGNOSTICS = True
AUTO_RECOVERY_ENABLED = True
TELEMETRY_ENABLED = True
CRASH_PREDICTION_ENABLED = True
PERFORMANCE_MONITORING = True

# Set up logger
def setup_logger():
    """Configure logging to write to a file in the appdata directory."""
    log_file = os.path.join(CRASH_LOG_DIR, "crash_handler.log")
    
    logger = logging.getLogger("allslain").getChild("launcher_store")
    logger.setLevel(logging.INFO)
    
    # Create file handler which logs even debug messages
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.INFO)
    
    # Create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    
    # Add the handlers to the logger
    logger.addHandler(fh)
    
    return logger

logger = setup_logger()

# === ADVANCED CRASH DATABASE ===
def init_crash_database():
    """Initialize SQLite database for crash analytics."""
    try:
        conn = sqlite3.connect(CRASH_DATABASE_PATH)
        cursor = conn.cursor()

        # Create crashes table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS crashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp DATETIME,
                error_code INTEGER,
                error_name TEXT,
                severity TEXT,
                error_hash TEXT,
                exception_type TEXT,
                error_message TEXT,
                traceback TEXT,
                system_info TEXT,
                user_actions TEXT,
                recovery_attempted BOOLEAN,
                recovery_successful BOOLEAN,
                sent_to_discord BOOLEAN,
                user_feedback TEXT
            )
        ''')

        # Create performance metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp DATETIME,
                cpu_usage REAL,
                memory_usage REAL,
                disk_usage REAL,
                network_latency REAL,
                active_threads INTEGER,
                open_files INTEGER
            )
        ''')

        # Create system diagnostics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_diagnostics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp DATETIME,
                diagnostic_type TEXT,
                diagnostic_data TEXT,
                status TEXT
            )
        ''')

        conn.commit()
        conn.close()
        logger.info("Crash database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize crash database: {e}")
        return False

def log_crash_to_database(error_code, error_name, severity, error_hash, exc_type, exc_value, traceback_str, system_info, user_actions=None):
    """Log crash details to database for analytics."""
    try:
        conn = sqlite3.connect(CRASH_DATABASE_PATH)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO crashes (
                session_id, timestamp, error_code, error_name, severity, error_hash,
                exception_type, error_message, traceback, system_info, user_actions,
                recovery_attempted, recovery_successful, sent_to_discord
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            SESSION_ID, datetime.now(), error_code, error_name, severity, error_hash,
            str(exc_type.__name__), str(exc_value), traceback_str, json.dumps(system_info),
            user_actions, False, False, False
        ))

        conn.commit()
        conn.close()
        return cursor.lastrowid
    except Exception as e:
        logger.error(f"Failed to log crash to database: {e}")
        return None

def get_crash_statistics():
    """Get crash statistics from database."""
    try:
        conn = sqlite3.connect(CRASH_DATABASE_PATH)
        cursor = conn.cursor()

        # Get crash counts by error code
        cursor.execute('''
            SELECT error_code, error_name, COUNT(*) as count, MAX(timestamp) as last_occurrence
            FROM crashes
            GROUP BY error_code, error_name
            ORDER BY count DESC
        ''')
        crash_stats = cursor.fetchall()

        # Get recent crashes
        cursor.execute('''
            SELECT timestamp, error_code, error_name, severity
            FROM crashes
            ORDER BY timestamp DESC
            LIMIT 10
        ''')
        recent_crashes = cursor.fetchall()

        # Get session statistics
        cursor.execute('''
            SELECT COUNT(*) as total_crashes,
                   COUNT(DISTINCT session_id) as sessions_with_crashes,
                   AVG(CASE WHEN recovery_successful THEN 1.0 ELSE 0.0 END) as recovery_rate
            FROM crashes
        ''')
        session_stats = cursor.fetchone()

        conn.close()

        return {
            "crash_stats": crash_stats,
            "recent_crashes": recent_crashes,
            "session_stats": session_stats
        }
    except Exception as e:
        logger.error(f"Failed to get crash statistics: {e}")
        return None

# === ERROR CLASSIFICATION FUNCTIONS ===
def classify_error(exc_type, exc_value, exc_tb):
    """Classify the error and return appropriate error code and category."""
    error_message = str(exc_value).lower()
    exc_type_name = exc_type.__name__.lower()
    traceback_str = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb)).lower()

    # File System Errors
    if 'filenotfounderror' in exc_type_name or 'game.log' in error_message:
        if 'game.log' in error_message:
            return 2001, "LOG_FILE_NOT_FOUND", "Critical"
        return 2000, "FILE_SYSTEM_ERROR", "High"

    if 'permissionerror' in exc_type_name or 'access denied' in error_message:
        return 2002, "LOG_FILE_ACCESS_DENIED", "High"

    # Network/API Errors
    if any(term in error_message for term in ['connection', 'network', 'timeout', 'requests']):
        if 'discord' in error_message or 'webhook' in error_message:
            return 3001, "DISCORD_WEBHOOK_FAILED", "Medium"
        if 'api' in error_message:
            return 3002, "API_CONNECTION_FAILED", "Medium"
        return 3000, "NETWORK_ERROR", "Medium"

    # Game Integration Errors
    if any(term in traceback_str for term in ['monitor_log', 'parse_death_event', 'death_regex']):
        if 'parse' in error_message:
            return 4002, "DEATH_EVENT_PARSE_ERROR", "Medium"
        return 4001, "GAME_LOG_MONITOR_FAILED", "High"

    # UI/Display Errors
    if any(term in traceback_str for term in ['tkinter', 'pyside6', 'qt', 'gui', 'overlay']):
        if 'overlay' in error_message:
            return 6001, "OVERLAY_CREATION_FAILED", "Medium"
        return 6000, "UI_ERROR", "Medium"

    # User Authentication Errors
    if any(term in error_message for term in ['user', 'login', 'registration', 'encryption']):
        if 'encryption' in error_message or 'decrypt' in error_message:
            return 5003, "USER_DATA_ENCRYPTION_FAILED", "High"
        if 'registration' in error_message:
            return 5001, "USER_REGISTRATION_FAILED", "Medium"
        return 5000, "USER_AUTH_ERROR", "Medium"

    # System Integration Errors
    if any(term in error_message for term in ['admin', 'elevation', 'registry', 'winreg']):
        if 'admin' in error_message or 'elevation' in error_message:
            return 7001, "ADMIN_ELEVATION_FAILED", "High"
        if 'registry' in error_message:
            return 7002, "REGISTRY_ACCESS_ERROR", "Medium"
        return 7000, "SYSTEM_INTEGRATION_ERROR", "Medium"

    # Crash Detection Errors
    if any(term in error_message for term in ['crash', 'vehicle', 'collision']):
        return 8000, "CRASH_DETECTION_ERROR", "Medium"

    # Memory Errors
    if 'memoryerror' in exc_type_name or 'out of memory' in error_message:
        return 1005, "MEMORY_ERROR", "Critical"

    # Thread Errors
    if 'thread' in error_message or 'threading' in traceback_str:
        return 1006, "THREAD_ERROR", "High"

    # Default classification
    return 1000, "GENERAL_APPLICATION_ERROR", "Medium"

def get_error_severity_color(severity):
    """Get color code for error severity."""
    severity_colors = {
        "Critical": 0xff0000,  # Red
        "High": 0xff6600,      # Orange
        "Medium": 0xffaa00,    # Yellow
        "Low": 0x00ff00        # Green
    }
    return severity_colors.get(severity, 0xaaaaaa)  # Default gray

def get_error_category_emoji(error_code):
    """Get emoji for error category based on error code."""
    if 1000 <= error_code < 2000:
        return "⚠️"  # General Application
    elif 2000 <= error_code < 3000:
        return "📁"  # File System
    elif 3000 <= error_code < 4000:
        return "🌐"  # Network/API
    elif 4000 <= error_code < 5000:
        return "🎮"  # Game Integration
    elif 5000 <= error_code < 6000:
        return "👤"  # User Authentication
    elif 6000 <= error_code < 7000:
        return "🖥️"  # UI/Display
    elif 7000 <= error_code < 8000:
        return "⚙️"  # System Integration
    elif 8000 <= error_code < 9000:
        return "💥"  # Crash/Vehicle Related
    else:
        return "❓"  # Unknown

def get_troubleshooting_suggestions(error_code, error_name):
    """Get troubleshooting suggestions based on error code."""
    suggestions = {
        2001: "• Check if Star Citizen is running\n• Verify Game.log path in settings\n• Ensure SC Kill Tracker has file access permissions",
        2002: "• Run SC Kill Tracker as Administrator\n• Check file permissions for Game.log\n• Verify antivirus isn't blocking access",
        3001: "• Check internet connection\n• Verify Discord webhook URL is correct\n• Check if Discord is experiencing outages",
        3002: "• Check internet connection\n• Verify Star Citizen API is accessible\n• Try restarting the application",
        4001: "• Restart Star Citizen\n• Check Game.log file isn't corrupted\n• Verify log file path is correct",
        4002: "• Update SC Kill Tracker to latest version\n• Check if Star Citizen log format has changed\n• Restart both applications",
        5001: "• Check username requirements (3+ characters)\n• Verify internet connection\n• Try a different username",
        6001: "• Check display settings and scaling\n• Update graphics drivers\n• Try running in compatibility mode",
        7001: "• Right-click and 'Run as Administrator'\n• Check User Account Control settings\n• Verify user has admin privileges",
        8000: "• Check Game.log for crash-related entries\n• Verify crash detection patterns\n• Update to latest version"
    }

    default_suggestion = "• Restart SC Kill Tracker\n• Check for updates\n• Contact support with error code"
    return suggestions.get(error_code, default_suggestion)

# === ADVANCED SYSTEM DIAGNOSTICS ===
def run_comprehensive_diagnostics():
    """Run comprehensive system diagnostics."""
    diagnostics = {}

    try:
        # System Performance
        diagnostics["cpu_usage"] = psutil.cpu_percent(interval=1)
        diagnostics["memory"] = psutil.virtual_memory()._asdict()
        diagnostics["disk"] = psutil.disk_usage('/')._asdict()

        # Network Diagnostics
        try:
            start_time = time.time()
            response = requests.get("https://discord.com", timeout=5)
            diagnostics["network_latency"] = (time.time() - start_time) * 1000
            diagnostics["network_status"] = "Connected"
        except:
            diagnostics["network_latency"] = -1
            diagnostics["network_status"] = "Disconnected"

        # Process Information
        if PSUTIL_AVAILABLE:
            try:
                current_process = psutil.Process()
                diagnostics["process_info"] = {
                    "pid": current_process.pid,
                    "memory_percent": current_process.memory_percent(),
                    "cpu_percent": current_process.cpu_percent(),
                    "num_threads": current_process.num_threads(),
                    "open_files": len(current_process.open_files()),
                    "connections": len(current_process.connections())
                }

                # Star Citizen Process Detection
                sc_processes = []
                for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent']):
                    if 'starcitizen' in proc.info['name'].lower():
                        sc_processes.append(proc.info)
                diagnostics["starcitizen_processes"] = sc_processes
            except Exception as e:
                diagnostics["process_info_error"] = str(e)
        else:
            diagnostics["process_info"] = "psutil not available"
            diagnostics["starcitizen_processes"] = "psutil not available"

        # File System Checks
        config = load_config()
        game_log_path = config.get("game_log_path", GAME_LOG_FILE)
        diagnostics["file_system"] = {
            "game_log_exists": os.path.exists(game_log_path),
            "game_log_readable": os.access(game_log_path, os.R_OK) if os.path.exists(game_log_path) else False,
            "config_dir_writable": os.access(CONFIG_DIR, os.W_OK),
            "crash_log_dir_writable": os.access(CRASH_LOG_DIR, os.W_OK)
        }

        # Registry Checks (Windows)
        if platform.system() == "Windows":
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
                    diagnostics["registry_accessible"] = True
            except:
                diagnostics["registry_accessible"] = False

        # DPI and Display Information
        try:
            user32 = ctypes.windll.user32
            diagnostics["display"] = {
                "screen_width": user32.GetSystemMetrics(0),
                "screen_height": user32.GetSystemMetrics(1),
                "dpi_aware": bool(user32.IsProcessDPIAware())
            }
        except:
            diagnostics["display"] = {"error": "Unable to get display info"}

    except Exception as e:
        diagnostics["diagnostic_error"] = str(e)

    return diagnostics

def monitor_performance():
    """Background performance monitoring."""
    while PERFORMANCE_MONITORING:
        try:
            metrics = {
                "cpu_usage": psutil.cpu_percent(),
                "memory_usage": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage('/').percent,
                "active_threads": threading.active_count(),
                "timestamp": datetime.now()
            }

            # Log to database if enabled
            if CRASH_ANALYTICS_ENABLED:
                try:
                    conn = sqlite3.connect(CRASH_DATABASE_PATH)
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO performance_metrics
                        (session_id, timestamp, cpu_usage, memory_usage, disk_usage, active_threads)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (SESSION_ID, metrics["timestamp"], metrics["cpu_usage"],
                          metrics["memory_usage"], metrics["disk_usage"], metrics["active_threads"]))
                    conn.commit()
                    conn.close()
                except:
                    pass  # Silently fail to avoid recursive crashes

            time.sleep(30)  # Monitor every 30 seconds
        except:
            break

def start_performance_monitoring():
    """Start background performance monitoring thread."""
    global DIAGNOSTIC_THREAD
    if PERFORMANCE_MONITORING and not DIAGNOSTIC_THREAD:
        DIAGNOSTIC_THREAD = threading.Thread(target=monitor_performance, daemon=True)
        DIAGNOSTIC_THREAD.start()
        logger.info("Performance monitoring started")

# === CRASH PREDICTION SYSTEM ===
def analyze_crash_patterns():
    """Analyze crash patterns to predict potential issues."""
    try:
        conn = sqlite3.connect(CRASH_DATABASE_PATH)
        cursor = conn.cursor()

        # Get crash frequency patterns
        cursor.execute('''
            SELECT error_code, COUNT(*) as frequency,
                   AVG(julianday('now') - julianday(timestamp)) as avg_days_since
            FROM crashes
            WHERE timestamp > datetime('now', '-30 days')
            GROUP BY error_code
            HAVING frequency > 1
            ORDER BY frequency DESC
        ''')
        patterns = cursor.fetchall()

        # Identify high-risk patterns
        risk_factors = []
        for error_code, frequency, avg_days in patterns:
            if frequency > 5:  # More than 5 crashes in 30 days
                risk_factors.append({
                    "error_code": error_code,
                    "frequency": frequency,
                    "risk_level": "High" if frequency > 10 else "Medium",
                    "avg_days_since": avg_days
                })

        conn.close()
        return risk_factors
    except Exception as e:
        logger.error(f"Failed to analyze crash patterns: {e}")
        return []

def send_telemetry_data(error_code, error_name, severity, system_info, anonymous=True):
    """Send anonymous telemetry data for crash analysis."""
    if not TELEMETRY_ENABLED:
        return

    try:
        # Anonymize sensitive data
        telemetry_data = {
            "error_code": error_code,
            "error_name": error_name,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "session_id": hashlib.md5(SESSION_ID.encode()).hexdigest()[:8] if anonymous else SESSION_ID,
            "system": {
                "os": system_info.get("system"),
                "release": system_info.get("release"),
                "machine": system_info.get("machine"),
                "python_version": system_info.get("python_version")
            },
            "app_info": {
                "version": "v0.1.3.6.2",  # Should be imported from main app
                "deployment": "Global"
            }
        }

        # Send to telemetry endpoint (if available)
        telemetry_url = "https://api.example.com/telemetry"  # Replace with actual endpoint
        # For now, just log locally
        telemetry_file = os.path.join(CRASH_LOG_DIR, "telemetry.jsonl")
        with open(telemetry_file, "a") as f:
            f.write(json.dumps(telemetry_data) + "\n")

        logger.info("Telemetry data logged")
    except Exception as e:
        logger.error(f"Failed to send telemetry: {e}")

# === ADVANCED CRASH EXPORT FEATURES ===
def export_crash_report(crash_id=None, format="json"):
    """Export detailed crash report for analysis."""
    try:
        conn = sqlite3.connect(CRASH_DATABASE_PATH)
        cursor = conn.cursor()

        if crash_id:
            cursor.execute('SELECT * FROM crashes WHERE id = ?', (crash_id,))
            crashes = [cursor.fetchone()]
        else:
            cursor.execute('SELECT * FROM crashes ORDER BY timestamp DESC LIMIT 10')
            crashes = cursor.fetchall()

        # Get column names
        cursor.execute('PRAGMA table_info(crashes)')
        columns = [col[1] for col in cursor.fetchall()]

        # Convert to dictionaries
        crash_data = []
        for crash in crashes:
            crash_dict = dict(zip(columns, crash))
            crash_data.append(crash_dict)

        # Export based on format
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format == "json":
            export_file = os.path.join(CRASH_LOG_DIR, f"crash_export_{timestamp}.json")
            with open(export_file, "w") as f:
                json.dump(crash_data, f, indent=2, default=str)

        elif format == "csv":
            import csv
            export_file = os.path.join(CRASH_LOG_DIR, f"crash_export_{timestamp}.csv")
            with open(export_file, "w", newline="") as f:
                if crash_data:
                    writer = csv.DictWriter(f, fieldnames=crash_data[0].keys())
                    writer.writeheader()
                    writer.writerows(crash_data)

        conn.close()
        return export_file
    except Exception as e:
        logger.error(f"Failed to export crash report: {e}")
        return None

def create_crash_summary_report():
    """Create a comprehensive crash summary report."""
    try:
        stats = get_crash_statistics()
        diagnostics = run_comprehensive_diagnostics()
        patterns = analyze_crash_patterns()

        report = {
            "generated_at": datetime.now().isoformat(),
            "session_id": SESSION_ID,
            "statistics": stats,
            "system_diagnostics": diagnostics,
            "risk_patterns": patterns,
            "recommendations": []
        }

        # Generate recommendations based on patterns
        if patterns:
            for pattern in patterns:
                if pattern["risk_level"] == "High":
                    report["recommendations"].append(
                        f"High crash frequency detected for error {pattern['error_code']}. "
                        f"Consider investigating root cause."
                    )

        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(CRASH_LOG_DIR, f"crash_summary_{timestamp}.json")
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        return report_file
    except Exception as e:
        logger.error(f"Failed to create crash summary report: {e}")
        return None

def load_image_from_url(url, max_size=(80, 80)):
    """Load an image from URL and resize it."""
    if not PIL_AVAILABLE:
        logger.warning("PIL not available, cannot load images")
        return None

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        image_data = io.BytesIO(response.content)
        img = Image.open(image_data)

        # Convert to RGBA if not already
        if img.mode != 'RGBA':
            img = img.convert('RGBA')

        # Resize while maintaining aspect ratio
        img.thumbnail(max_size, Image.LANCZOS)
        return ImageTk.PhotoImage(img)
    except Exception as e:
        logger.error(f"Failed to load logo image: {e}")
        return None

def validate_webhook_url(url):
    """Basic validation of Discord webhook URL."""
    if not url.startswith("https://discord.com/api/webhooks/"):
        raise ValueError("Invalid Discord webhook URL")
    return url

def load_config():
    """Load configuration with fallbacks and environment overrides."""
    config_path = os.path.join(CONFIG_DIR, "crash_config.json")
    default_config = {
        "webhook_url": CRASH_REPORT_WEBHOOK_URL,
        "game_log_path": GAME_LOG_FILE,
        "logo_url": LOGO_URL
    }
    
    try:
        # Try to load existing config
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                loaded_config = json.load(f)
                # Merge with defaults
                default_config.update(loaded_config)
        
        # Allow config override from environment variables
        if "CRASH_REPORT_WEBHOOK" in os.environ:
            default_config["webhook_url"] = validate_webhook_url(os.environ["CRASH_REPORT_WEBHOOK"])
        if "GAME_LOG_PATH" in os.environ:
            default_config["game_log_path"] = os.environ["GAME_LOG_PATH"]
        if "LOGO_URL" in os.environ:
            default_config["logo_url"] = os.environ["LOGO_URL"]
            
        # Save the final config
        with open(config_path, 'w') as f:
            json.dump(default_config, f, indent=4)
            
        return default_config
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return default_config

def get_system_info():
    """Collect basic system information to help diagnose issues."""
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "executable": sys.executable,
        "argv": sys.argv,
        "cwd": os.getcwd(),
        "timestamp": datetime.now().isoformat(),
        "appdata_dir": APP_DATA_DIR
    }

    # Add SCKillTrac-specific information
    try:
        # Check if Game.log exists and get its status
        config = load_config()
        game_log_path = config.get("game_log_path", GAME_LOG_FILE)
        if os.path.exists(game_log_path):
            stat = os.stat(game_log_path)
            info["game_log_exists"] = True
            info["game_log_size"] = stat.st_size
            info["game_log_modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
        else:
            info["game_log_exists"] = False

        # Check for running Star Citizen processes
        try:
            import psutil
            sc_processes = []
            for proc in psutil.process_iter(['pid', 'name']):
                if 'starcitizen' in proc.info['name'].lower():
                    sc_processes.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
            info["starcitizen_processes"] = sc_processes if sc_processes else ["None"]
        except:
            info["starcitizen_processes"] = ["Unable to detect"]

        # Check network connectivity
        try:
            import requests
            response = requests.get("https://discord.com", timeout=5)
            info["network_status"] = "Connected" if response.status_code == 200 else f"Error: {response.status_code}"
        except:
            info["network_status"] = "Disconnected or Error"

    except Exception as e:
        info["sckilltrack_info_error"] = str(e)

    return info

# === ADVANCED AUTO-RECOVERY SYSTEM ===
def attempt_auto_recovery(error_code, error_name, exc_type, exc_value):
    """Attempt automatic recovery based on error type."""
    recovery_actions = []
    recovery_successful = False

    try:
        if error_code == 2001:  # LOG_FILE_NOT_FOUND
            recovery_actions.append("Attempting to locate Game.log file...")
            # Try to find Game.log in common locations
            common_paths = [
                r"C:\Program Files\Roberts Space Industries\StarCitizen\LIVE\Game.log",
                r"D:\Program Files\Roberts Space Industries\StarCitizen\LIVE\Game.log",
                r"C:\Program Files\Roberts Space Industries\StarCitizen\PTU\Game.log",
            ]

            for path in common_paths:
                if os.path.exists(path):
                    # Update config with found path
                    config = load_config()
                    config["game_log_path"] = path
                    config_path = os.path.join(CONFIG_DIR, "crash_config.json")
                    with open(config_path, 'w') as f:
                        json.dump(config, f, indent=4)
                    recovery_actions.append(f"Found Game.log at: {path}")
                    recovery_successful = True
                    break

        elif error_code == 2002:  # LOG_FILE_ACCESS_DENIED
            recovery_actions.append("Attempting to fix file permissions...")
            # Try to change file permissions
            config = load_config()
            game_log_path = config.get("game_log_path", GAME_LOG_FILE)
            if os.path.exists(game_log_path):
                try:
                    os.chmod(game_log_path, 0o644)
                    recovery_actions.append("File permissions updated")
                    recovery_successful = True
                except:
                    recovery_actions.append("Failed to update permissions - admin rights may be required")

        elif error_code == 3001:  # DISCORD_WEBHOOK_FAILED
            recovery_actions.append("Testing alternative webhook endpoints...")
            # Test webhook connectivity
            try:
                response = requests.get("https://discord.com/api/v10/gateway", timeout=5)
                if response.status_code == 200:
                    recovery_actions.append("Discord API is accessible")
                    recovery_successful = True
                else:
                    recovery_actions.append("Discord API returned error")
            except:
                recovery_actions.append("Discord API is not accessible")

        elif error_code == 6001:  # OVERLAY_CREATION_FAILED
            recovery_actions.append("Attempting to reset display settings...")
            # Reset DPI awareness
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
                recovery_actions.append("DPI awareness reset")
                recovery_successful = True
            except:
                recovery_actions.append("Failed to reset DPI awareness")

        elif error_code == 7001:  # ADMIN_ELEVATION_FAILED
            recovery_actions.append("Checking current user privileges...")
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if is_admin:
                    recovery_actions.append("Application is running with admin privileges")
                    recovery_successful = True
                else:
                    recovery_actions.append("Application needs to be run as administrator")
            except:
                recovery_actions.append("Unable to check admin privileges")

        # Log recovery attempt to database
        if CRASH_ANALYTICS_ENABLED:
            try:
                conn = sqlite3.connect(CRASH_DATABASE_PATH)
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE crashes
                    SET recovery_attempted = ?, recovery_successful = ?, user_actions = ?
                    WHERE error_code = ? AND session_id = ?
                    ORDER BY timestamp DESC LIMIT 1
                ''', (True, recovery_successful, "\n".join(recovery_actions), error_code, SESSION_ID))
                conn.commit()
                conn.close()
            except:
                pass

    except Exception as e:
        recovery_actions.append(f"Recovery attempt failed: {str(e)}")

    return recovery_successful, recovery_actions

def log_crash_locally(error_message, system_info):
    """Save crash reports locally for offline analysis."""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(CRASH_LOG_DIR, f"crash_{timestamp}.log")
        
        with open(filename, "w") as f:
            f.write(f"=== CRASH REPORT {timestamp} ===\n")
            f.write("\n=== SYSTEM INFO ===\n")
            for k, v in system_info.items():
                f.write(f"{k}: {v}\n")
            f.write("\n=== ERROR DETAILS ===\n")
            f.write(error_message)
            
        logger.info(f"Crash logged locally at {filename}")
        return filename
    except Exception as e:
        logger.error(f"Failed to log crash locally: {e}")
        return None

def detect_variant(log_file_path) -> str:
    """Dynamically detect the variant of SCKillTrac based on Game.log content."""
    try:
        if not os.path.exists(log_file_path):
            return "Global"
            
        with open(log_file_path, "r") as log_file:
            log_content = log_file.read()

            # Regex pattern to dynamically detect any variant inside the square brackets
            pattern = r"SCKillTrac\[(.*?)\]"
            match = re.search(pattern, log_content)
            
            return match.group(1) if match else "Global"

    except Exception as e:
        logger.error(f"Error detecting variant: {e}")
        return "Global"  # Fallback to "Global" if detection fails

def send_file_to_discord(file_path, config):
    """Send a file to the Discord webhook."""
    try:
        if not os.path.exists(file_path):
            logger.warning(f"File {file_path} not found, skipping upload")
            return False

        with open(file_path, 'rb') as f:
            file = {
                'file': (os.path.basename(file_path), f, 'application/octet-stream')
            }
            data = {
                'content': 'Crash report with attached log file.'
            }
            response = requests.post(config["webhook_url"], data=data, files=file)
            response.raise_for_status()
            logger.info(f"File {file_path} sent successfully to Discord.")
            return True
    except Exception as e:
        logger.error(f"Failed to send file to Discord: {e}")
        return False

def create_styled_button(parent, text, command, bg=BUTTON_BG, hover_bg=BUTTON_HOVER_BG, **kwargs):
    """Create a styled button with hover effects and optional icon"""
    button = tk.Button(
        parent,
        text=text,
        command=command,
        font=BUTTON_FONT,
        bg=bg,
        fg=BUTTON_FG,
        activebackground=hover_bg,
        activeforeground=BUTTON_FG,
        bd=0,
        relief="flat",
        padx=15,
        pady=8,
        cursor="hand2",
        **kwargs
    )
    
    # Add hover effect
    def on_enter(e):
        button['background'] = hover_bg
    
    def on_leave(e):
        button['background'] = bg
    
    button.bind("<Enter>", on_enter)
    button.bind("<Leave>", on_leave)
    
    return button

def show_sending_animation(dialog, progress_var):
    """Display a sending animation with progress bar"""
    sending_frame = tk.Frame(dialog, bg=BACKGROUND_COLOR, padx=20, pady=20)
    sending_frame.place(relx=0.5, rely=0.5, anchor="center", 
                       relwidth=0.6, relheight=0.3)
    
    tk.Label(
        sending_frame,
        text="Sending Crash Report...",
        font=HEADER_FONT,
        fg=TEXT_COLOR,
        bg=BACKGROUND_COLOR
    ).pack(pady=(0, 15))
    
    progress = ttk.Progressbar(
        sending_frame, 
        orient="horizontal",
        mode="determinate",
        variable=progress_var
    )
    progress.pack(fill="x", pady=10, padx=20)
    
    return sending_frame

def show_send_success(dialog):
    """Show success message after report is sent"""
    success_frame = tk.Frame(dialog, bg=BACKGROUND_COLOR, padx=20, pady=20)
    success_frame.place(relx=0.5, rely=0.5, anchor="center", 
                       relwidth=0.6, relheight=0.3)
    
    tk.Label(
        success_frame,
        text="✓ Report Sent Successfully",
        font=HEADER_FONT,
        fg="#4caf50",  # Green color
        bg=BACKGROUND_COLOR
    ).pack(pady=(0, 15))
    
    message = tk.Label(
        success_frame,
        text="Thank you for helping improve Star Citizen Kill Tracker.",
        font=NORMAL_FONT,
        fg=TEXT_COLOR,
        bg=BACKGROUND_COLOR,
        wraplength=250
    )
    message.pack(pady=5, expand=True, fill="both")
    
    # Close button
    def on_close():
        dialog.destroy()
        dialog.master.destroy()
        sys.exit(1)
        
    close_btn = create_styled_button(success_frame, "Close", on_close)
    close_btn.pack(pady=15)
    
    return success_frame

def create_advanced_crash_dialog(root, exc_value, error_message, logo_image, error_code=None, error_name=None, severity=None, recovery_actions=None, diagnostics=None):
    dialog = tk.Toplevel(root)
    dialog.title(f"SC Kill Tracker - Advanced Error Report {f'[{error_code}]' if error_code else ''}")
    dialog.geometry(f"{DEFAULT_WINDOW_WIDTH + 200}x{DEFAULT_WINDOW_HEIGHT + 300}")
    dialog.configure(bg=BACKGROUND_COLOR)
    dialog.minsize(MIN_WINDOW_WIDTH + 100, MIN_WINDOW_HEIGHT + 200)
    dialog.resizable(True, True)
    
    # Make dialog modal
    dialog.grab_set()
    dialog.focus_force()
    
    # Ensure the dialog doesn't show minimized
    dialog.attributes('-topmost', True)
    dialog.update()
    dialog.attributes('-topmost', False)
    
    # Configure responsive grid layout
    dialog.grid_columnconfigure(0, weight=1)
    dialog.grid_rowconfigure(0, weight=0)  # Header doesn't grow
    dialog.grid_rowconfigure(1, weight=1)  # Content grows (now contains notebook)
    dialog.grid_rowconfigure(2, weight=0)  # Notice doesn't grow
    dialog.grid_rowconfigure(3, weight=0)  # Buttons don't grow
    
    # ----- HEADER SECTION -----
    header_frame = tk.Frame(dialog, bg=HEADER_COLOR, pady=15)
    header_frame.grid(row=0, column=0, sticky="ew")
    header_frame.grid_columnconfigure(1, weight=1)
    
    # Header with logo and title in horizontal layout
    if logo_image:
        logo_label = tk.Label(header_frame, image=logo_image, bg=HEADER_COLOR)
        logo_label.image = logo_image  # Keep reference
        logo_label.grid(row=0, column=0, padx=(15, 10))
    
    title_label = tk.Label(
        header_frame, 
        text="Star Citizen Kill Tracker", 
        font=HEADER_LARGE_FONT,
        fg=TEXT_COLOR,
        bg=HEADER_COLOR
    )
    title_label.grid(row=0, column=1, sticky="w")
    
    subtitle_label = tk.Label(
        header_frame, 
        text="Crash Report", 
        font=SUBHEADER_FONT,
        fg=TEXT_COLOR,
        bg=HEADER_COLOR
    )
    subtitle_label.grid(row=1, column=1, sticky="w")

    # ----- ADVANCED TABBED CONTENT SECTION -----
    content_frame = tk.Frame(dialog, bg=BACKGROUND_COLOR, padx=PADDING_LARGE, pady=PADDING_LARGE)
    content_frame.grid(row=1, column=0, sticky="nsew")
    content_frame.grid_columnconfigure(0, weight=1)
    content_frame.grid_rowconfigure(0, weight=1)

    # Create notebook for tabs
    notebook = ttk.Notebook(content_frame)
    notebook.grid(row=0, column=0, sticky="nsew")

    # Style the notebook
    style = ttk.Style()
    style.configure('TNotebook', background=BACKGROUND_COLOR)
    style.configure('TNotebook.Tab', padding=[12, 8])

    # === ERROR OVERVIEW TAB ===
    overview_frame = tk.Frame(notebook, bg=BACKGROUND_COLOR)
    notebook.add(overview_frame, text="📋 Error Overview")
    overview_frame.grid_columnconfigure(0, weight=1)
    overview_frame.grid_rowconfigure(2, weight=1)
    
    # Error classification display
    if error_code and error_name and severity:
        classification_frame = tk.Frame(overview_frame, bg=TEXT_AREA_BG, bd=1, relief="solid")
        classification_frame.grid(row=0, column=0, sticky="ew", pady=(0, PADDING_MEDIUM))
        classification_frame.grid_columnconfigure(1, weight=1)

        # Error emoji and code
        tk.Label(
            classification_frame,
            text=get_error_category_emoji(error_code),
            font=(FONT_FAMILY, FONT_SIZES["header"], "bold"),
            fg=TEXT_COLOR,
            bg=TEXT_AREA_BG
        ).grid(row=0, column=0, padx=10, pady=10)

        # Error details
        error_details = f"Error Code: {error_code}\nType: {error_name}\nSeverity: {severity}"
        tk.Label(
            classification_frame,
            text=error_details,
            font=NORMAL_FONT,
            fg=TEXT_COLOR,
            bg=TEXT_AREA_BG,
            justify="left",
            anchor="w"
        ).grid(row=0, column=1, sticky="ew", padx=10, pady=10)

    # Error summary
    tk.Label(
        overview_frame,
        text="An unexpected error has occurred:",
        font=NORMAL_FONT,
        fg=TEXT_COLOR,
        bg=BACKGROUND_COLOR,
        anchor="w"
    ).grid(row=1, column=0, sticky="ew", pady=(0, PADDING_SMALL))
    
    # Error message in a bordered frame
    error_frame = tk.Frame(
        overview_frame,
        bg=TEXT_AREA_BG,
        bd=1,
        relief="solid",
        highlightbackground=BORDER_COLOR,
        highlightthickness=1
    )
    error_frame.grid(row=2, column=0, sticky="nsew", pady=(0, PADDING_MEDIUM))
    error_frame.grid_columnconfigure(0, weight=1)
    error_frame.grid_rowconfigure(0, weight=1)

    # Scrollable text widget for error message
    error_text = scrolledtext.ScrolledText(
        error_frame,
        wrap="word",
        font=CODE_FONT,
        fg=ERROR_COLOR,
        bg=TEXT_AREA_BG,
        bd=0,
        padx=5,
        pady=5,
        height=8,
        insertbackground=TEXT_COLOR,
        selectbackground="#4c4c4c"
    )
    error_text.insert(tk.END, str(exc_value))
    error_text.config(state=tk.DISABLED)
    error_text.grid(row=0, column=0, sticky="nsew")

    # === DIAGNOSTICS TAB ===
    diagnostics_frame = tk.Frame(notebook, bg=BACKGROUND_COLOR)
    notebook.add(diagnostics_frame, text="🔍 System Diagnostics")
    diagnostics_frame.grid_columnconfigure(0, weight=1)
    diagnostics_frame.grid_rowconfigure(0, weight=1)

    diagnostics_text = scrolledtext.ScrolledText(
        diagnostics_frame,
        wrap="word",
        font=CODE_FONT,
        fg=TEXT_COLOR,
        bg=TEXT_AREA_BG,
        bd=1,
        relief="solid",
        padx=5,
        pady=5,
        insertbackground=TEXT_COLOR,
        selectbackground="#4c4c4c"
    )

    # Populate diagnostics
    if diagnostics:
        diagnostics_text.insert(tk.END, "=== SYSTEM DIAGNOSTICS ===\n\n")
        for key, value in diagnostics.items():
            if isinstance(value, dict):
                diagnostics_text.insert(tk.END, f"{key.upper()}:\n")
                for subkey, subvalue in value.items():
                    diagnostics_text.insert(tk.END, f"  {subkey}: {subvalue}\n")
                diagnostics_text.insert(tk.END, "\n")
            else:
                diagnostics_text.insert(tk.END, f"{key}: {value}\n")
    else:
        diagnostics_text.insert(tk.END, "Running diagnostics...\n")
        # Run diagnostics in background
        def run_diagnostics():
            diag_data = run_comprehensive_diagnostics()
            diagnostics_text.config(state=tk.NORMAL)
            diagnostics_text.delete(1.0, tk.END)
            diagnostics_text.insert(tk.END, "=== SYSTEM DIAGNOSTICS ===\n\n")
            for key, value in diag_data.items():
                if isinstance(value, dict):
                    diagnostics_text.insert(tk.END, f"{key.upper()}:\n")
                    for subkey, subvalue in value.items():
                        diagnostics_text.insert(tk.END, f"  {subkey}: {subvalue}\n")
                    diagnostics_text.insert(tk.END, "\n")
                else:
                    diagnostics_text.insert(tk.END, f"{key}: {value}\n")
            diagnostics_text.config(state=tk.DISABLED)

        threading.Thread(target=run_diagnostics, daemon=True).start()

    diagnostics_text.config(state=tk.DISABLED)
    diagnostics_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

    # === RECOVERY TAB ===
    recovery_frame = tk.Frame(notebook, bg=BACKGROUND_COLOR)
    notebook.add(recovery_frame, text="🔧 Auto Recovery")
    recovery_frame.grid_columnconfigure(0, weight=1)
    recovery_frame.grid_rowconfigure(1, weight=1)

    # Recovery status
    recovery_status_frame = tk.Frame(recovery_frame, bg=TEXT_AREA_BG, bd=1, relief="solid")
    recovery_status_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
    recovery_status_frame.grid_columnconfigure(1, weight=1)

    if recovery_actions:
        status_color = "#4caf50" if any("successful" in action.lower() for action in recovery_actions) else "#ff9800"
        status_text = "✓ Recovery Attempted" if recovery_actions else "⚠ No Recovery Attempted"
    else:
        status_color = "#666666"
        status_text = "⚠ No Recovery Attempted"

    tk.Label(
        recovery_status_frame,
        text="🔧",
        font=(FONT_FAMILY, FONT_SIZES["header"]),
        fg=status_color,
        bg=TEXT_AREA_BG
    ).grid(row=0, column=0, padx=10, pady=10)

    tk.Label(
        recovery_status_frame,
        text=status_text,
        font=(FONT_FAMILY, FONT_SIZES["normal"], "bold"),
        fg=status_color,
        bg=TEXT_AREA_BG,
        anchor="w"
    ).grid(row=0, column=1, sticky="ew", padx=10, pady=10)

    # Recovery actions log
    recovery_text = scrolledtext.ScrolledText(
        recovery_frame,
        wrap="word",
        font=CODE_FONT,
        fg=TEXT_COLOR,
        bg=TEXT_AREA_BG,
        bd=1,
        relief="solid",
        padx=5,
        pady=5,
        insertbackground=TEXT_COLOR,
        selectbackground="#4c4c4c"
    )

    if recovery_actions:
        recovery_text.insert(tk.END, "=== AUTO RECOVERY LOG ===\n\n")
        for i, action in enumerate(recovery_actions, 1):
            recovery_text.insert(tk.END, f"{i}. {action}\n")
    else:
        recovery_text.insert(tk.END, "No recovery actions were attempted for this error.\n\n")
        if error_code:
            suggestions = get_troubleshooting_suggestions(error_code, error_name)
            recovery_text.insert(tk.END, "TROUBLESHOOTING SUGGESTIONS:\n\n")
            recovery_text.insert(tk.END, suggestions)

    recovery_text.config(state=tk.DISABLED)
    recovery_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

    # === ANALYTICS TAB ===
    analytics_frame = tk.Frame(notebook, bg=BACKGROUND_COLOR)
    notebook.add(analytics_frame, text="📊 Crash Analytics")
    analytics_frame.grid_columnconfigure(0, weight=1)
    analytics_frame.grid_rowconfigure(0, weight=1)

    analytics_text = scrolledtext.ScrolledText(
        analytics_frame,
        wrap="word",
        font=CODE_FONT,
        fg=TEXT_COLOR,
        bg=TEXT_AREA_BG,
        bd=1,
        relief="solid",
        padx=5,
        pady=5,
        insertbackground=TEXT_COLOR,
        selectbackground="#4c4c4c"
    )

    # Load and display crash statistics
    def load_analytics():
        analytics_text.config(state=tk.NORMAL)
        analytics_text.insert(tk.END, "Loading crash analytics...\n")

        try:
            stats = get_crash_statistics()
            if stats:
                analytics_text.delete(1.0, tk.END)
                analytics_text.insert(tk.END, "=== CRASH ANALYTICS ===\n\n")

                # Session statistics
                if stats["session_stats"]:
                    total_crashes, sessions_with_crashes, recovery_rate = stats["session_stats"]
                    analytics_text.insert(tk.END, f"SESSION STATISTICS:\n")
                    analytics_text.insert(tk.END, f"Total Crashes: {total_crashes}\n")
                    analytics_text.insert(tk.END, f"Sessions with Crashes: {sessions_with_crashes}\n")
                    analytics_text.insert(tk.END, f"Recovery Success Rate: {recovery_rate:.1%}\n\n")

                # Top crash types
                if stats["crash_stats"]:
                    analytics_text.insert(tk.END, "TOP CRASH TYPES:\n")
                    for error_code, error_name, count, last_occurrence in stats["crash_stats"][:5]:
                        analytics_text.insert(tk.END, f"• {error_name} ({error_code}): {count} times\n")
                        analytics_text.insert(tk.END, f"  Last: {last_occurrence}\n")
                    analytics_text.insert(tk.END, "\n")

                # Recent crashes
                if stats["recent_crashes"]:
                    analytics_text.insert(tk.END, "RECENT CRASHES:\n")
                    for timestamp, error_code, error_name, severity in stats["recent_crashes"]:
                        analytics_text.insert(tk.END, f"• {timestamp}: {error_name} ({severity})\n")
            else:
                analytics_text.delete(1.0, tk.END)
                analytics_text.insert(tk.END, "No crash analytics available.\n")
        except Exception as e:
            analytics_text.delete(1.0, tk.END)
            analytics_text.insert(tk.END, f"Error loading analytics: {e}\n")

        analytics_text.config(state=tk.DISABLED)

    # Load analytics in background
    threading.Thread(target=load_analytics, daemon=True).start()

    analytics_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

    # === TECHNICAL DETAILS TAB ===
    technical_frame = tk.Frame(notebook, bg=BACKGROUND_COLOR)
    notebook.add(technical_frame, text="🔬 Technical Details")
    technical_frame.grid_columnconfigure(0, weight=1)
    technical_frame.grid_rowconfigure(0, weight=1)

    technical_text = scrolledtext.ScrolledText(
        technical_frame,
        wrap="word",
        font=CODE_FONT,
        fg=TEXT_COLOR,
        bg=TEXT_AREA_BG,
        bd=1,
        relief="solid",
        padx=5,
        pady=5,
        insertbackground=TEXT_COLOR,
        selectbackground="#4c4c4c"
    )
    technical_text.insert(tk.END, f"=== TECHNICAL DETAILS ===\n\n")
    technical_text.insert(tk.END, f"FULL TRACEBACK:\n{error_message}\n\n")
    technical_text.insert(tk.END, f"SESSION ID: {SESSION_ID}\n")
    technical_text.insert(tk.END, f"TIMESTAMP: {datetime.now().isoformat()}\n")
    technical_text.config(state=tk.DISABLED)
    technical_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
    
    # Technical details
    details_label = tk.Label(
        content_frame,
        text="Technical Details",
        font=(FONT_FAMILY, FONT_SIZES["normal"], "bold"),
        fg=TEXT_COLOR,
        bg=BACKGROUND_COLOR,
        anchor="w"
    )
    details_label.grid(row=2, column=0, sticky="ew", pady=(PADDING_MEDIUM, PADDING_SMALL))
    
    # Technical details text area with custom border
    details_container = tk.Frame(
        content_frame,
        bg=TEXT_AREA_BG,
        bd=1,
        relief="solid",
        highlightbackground=BORDER_COLOR,
        highlightthickness=1
    )
    details_container.grid(row=3, column=0, sticky="nsew")
    details_container.grid_columnconfigure(0, weight=1)
    details_container.grid_rowconfigure(0, weight=1)
    
    error_text = scrolledtext.ScrolledText(
        details_container,
        wrap="word",
        font=CODE_FONT,
        fg=TEXT_COLOR,
        bg=TEXT_AREA_BG,
        bd=0,
        padx=5,
        pady=5,
        insertbackground=TEXT_COLOR,
        selectbackground="#4c4c4c"
    )
    error_text.insert(tk.END, error_message[:5000])
    error_text.config(state=tk.DISABLED)
    error_text.grid(row=0, column=0, sticky="nsew")
    
    # ----- PRIVACY NOTICE -----
    notice_frame = tk.Frame(
        dialog, 
        bg="#192734", 
        padx=PADDING_MEDIUM, 
        pady=PADDING_MEDIUM, 
        bd=1, 
        relief="solid", 
        highlightbackground=BORDER_COLOR, 
        highlightthickness=1
    )
    notice_frame.grid(row=2, column=0, sticky="ew", padx=PADDING_LARGE, pady=(0, PADDING_MEDIUM))
    notice_frame.grid_columnconfigure(0, weight=1)
    
    tk.Label(
        notice_frame,
        text="Privacy Notice",
        font=(FONT_FAMILY, FONT_SIZES["normal"], "bold"),
        fg=TEXT_COLOR,
        bg="#192734",
        anchor="w"
    ).grid(row=0, column=0, sticky="ew")
    
    tk.Label(
        notice_frame,
        text="Crash reports help us improve the application. They include error details and basic system information. No personal data will be collected.",
        font=SMALL_FONT,
        fg="#cccccc",
        bg="#192734",
        wraplength=580,
        justify="left",
        anchor="w"
    ).grid(row=1, column=0, sticky="ew", pady=(PADDING_SMALL, 0))
    
    # ----- BUTTON SECTION -----
    button_frame = tk.Frame(dialog, bg=BACKGROUND_COLOR, padx=PADDING_LARGE, pady=PADDING_MEDIUM)
    button_frame.grid(row=3, column=0, sticky="ew")
    button_frame.grid_columnconfigure(0, weight=1)  # Left side (checkbox) expands
    button_frame.grid_columnconfigure(1, weight=0)  # Right side (buttons) doesn't expand
    
    # Add a checkbox for restarting
    restart_var = tk.BooleanVar(value=True)
    restart_check = tk.Checkbutton(
        button_frame, 
        text="Restart application after closing",
        variable=restart_var,
        font=NORMAL_FONT,
        fg=TEXT_COLOR,
        bg=BACKGROUND_COLOR,
        selectcolor=TEXT_AREA_BG,
        activebackground=BACKGROUND_COLOR,
        activeforeground=TEXT_COLOR
    )
    restart_check.grid(row=0, column=0, sticky="w")
    
    # Create a right-aligned container for buttons
    button_container = tk.Frame(button_frame, bg=BACKGROUND_COLOR)
    button_container.grid(row=0, column=1, sticky="e")
    
    # Configure window resize event to adjust wraplength dynamically
    def on_resize(event):
        # Only process if it's the dialog that's resizing
        if event.widget == dialog:
            # Update wraplength for text elements
            new_width = event.width - (PADDING_LARGE * 2) - 20  # Account for padding

            # Update any label widgets that need resizing
            try:
                for widget in notice_frame.winfo_children():
                    if isinstance(widget, tk.Label):
                        widget.config(wraplength=new_width)
            except:
                pass  # Ignore if notice_frame doesn't exist in advanced dialog
                    
    # Bind the resize event
    dialog.bind("<Configure>", on_resize)
    
    return dialog, button_container, restart_var

def handle_crash(exc_type, exc_value, exc_tb):
    """Custom crash handler for uncaught exceptions."""
    global LAST_CRASH_TIME, LAST_CRASH_HASH

    try:
        config = load_config()
        error_message = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
        error_hash = hashlib.md5(error_message.encode()).hexdigest()
        system_info = get_system_info()

        # Classify the error
        error_code, error_name, severity = classify_error(exc_type, exc_value, exc_tb)
        error_emoji = get_error_category_emoji(error_code)

        # Enhanced logging with error classification
        logger.critical(f"Unhandled exception [Code: {error_code}] [{error_name}] [Severity: {severity}]: {error_message}")

        # Add error classification to system info
        system_info.update({
            "error_code": error_code,
            "error_name": error_name,
            "error_severity": severity,
            "error_category": error_emoji,
            "error_hash": error_hash
        })

        # Check for duplicate crashes
        now = datetime.now()
        if (LAST_CRASH_TIME and
            (now - LAST_CRASH_TIME) < timedelta(minutes=CRASH_COOLDOWN_MINUTES) and
            error_hash == LAST_CRASH_HASH):
            logger.info("Duplicate crash detected within cooldown period - not showing dialog")
            return

        LAST_CRASH_TIME = now
        LAST_CRASH_HASH = error_hash
        
        # Initialize crash database if not already done
        if not os.path.exists(CRASH_DATABASE_PATH):
            init_crash_database()

        # Log crash to database for analytics
        crash_id = log_crash_to_database(error_code, error_name, severity, error_hash, exc_type, exc_value, error_message, system_info)

        # Attempt auto-recovery if enabled
        recovery_successful = False
        recovery_actions = []
        if AUTO_RECOVERY_ENABLED:
            recovery_successful, recovery_actions = attempt_auto_recovery(error_code, error_name, exc_type, exc_value)
            logger.info(f"Auto-recovery attempted: {recovery_successful}")

        # Run comprehensive diagnostics
        diagnostics = None
        if ADVANCED_DIAGNOSTICS:
            diagnostics = run_comprehensive_diagnostics()

        # Always log crashes locally first
        local_log_path = log_crash_locally(error_message, system_info)
        
        # Set up Tkinter
        root = tk.Tk()
        root.withdraw()
        
        # Style the ttk widgets for consistency
        style = ttk.Style()
        style.theme_use('default')
        style.configure(
            "TProgressbar", 
            thickness=8,
            troughcolor=BACKGROUND_COLOR,
            background=BUTTON_BG,
            borderwidth=0
        )
        
        # Load logo image
        logo_image = load_image_from_url(config["logo_url"])
        
        # Create advanced custom dialog
        dialog, button_container, restart_var = create_advanced_crash_dialog(
            root, exc_value, error_message, logo_image,
            error_code, error_name, severity, recovery_actions, diagnostics
        )
        
        # Progress variable for animations
        progress_var = tk.IntVar(value=0)
        
        # Dialog actions
        def on_send():
            # Show sending animation
            sending_frame = show_sending_animation(dialog, progress_var)
            dialog.update()
            
            # Simulate progress (in a real app, this would update as the report is processed)
            for i in range(0, 101, 5):
                progress_var.set(i)
                dialog.update()
                dialog.after(50)  # Short delay for animation effect
            
            # Send the actual report
            send_crash_report(config, exc_value, error_message, system_info, local_log_path)
            
            # Remove sending frame
            sending_frame.destroy()
            
            # Show success message
            success_frame = show_send_success(dialog)
            
            # If restart is checked, restart after a delay
            if restart_var.get():
                dialog.after(2000, lambda: restart_application(dialog))
                
        def restart_application(dialog=None):
            if dialog:
                dialog.destroy()
            root.destroy()
            os.execv(sys.executable, [sys.executable] + sys.argv)
            
        def on_dont_send():
            if restart_var.get():
                restart_application(dialog)
            else:
                dialog.destroy()
                root.destroy()
                sys.exit(1)
        
        # Add styled buttons with some spacing between them and clear labels
        exit_btn = create_styled_button(
            button_container, 
            "Close", 
            lambda: on_dont_send(),
            bg=BUTTON_NEUTRAL_BG,
            hover_bg=BUTTON_NEUTRAL_HOVER_BG
        )
        exit_btn.pack(side="right", padx=5)
        
        restart_btn = create_styled_button(
            button_container, 
            "Restart Now", 
            lambda: restart_application(dialog),
            bg=BUTTON_NEUTRAL_BG,
            hover_bg=BUTTON_NEUTRAL_HOVER_BG
        )
        restart_btn.pack(side="right", padx=5)
        
        dont_send_btn = create_styled_button(
            button_container, 
            "Don't Send", 
            on_dont_send,
            bg=BUTTON_DENY_BG,
            hover_bg=BUTTON_DENY_HOVER_BG
        )
        dont_send_btn.pack(side="right", padx=5)
        
        # Advanced action buttons
        export_btn = create_styled_button(
            button_container,
            "📊 Export Report",
            lambda: export_and_show_path(),
            bg=BUTTON_NEUTRAL_BG,
            hover_bg=BUTTON_NEUTRAL_HOVER_BG
        )
        export_btn.pack(side="right", padx=5)

        def export_and_show_path():
            try:
                export_path = create_crash_summary_report()
                if export_path:
                    messagebox.showinfo("Export Complete", f"Crash report exported to:\n{export_path}")
                else:
                    messagebox.showerror("Export Failed", "Failed to export crash report.")
            except Exception as e:
                messagebox.showerror("Export Error", f"Error during export: {e}")

        send_btn = create_styled_button(
            button_container,
            "📤 Send Report",
            on_send
        )
        send_btn.pack(side="right", padx=5)
        
        # Center dialog on screen
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f"{width}x{height}+{x}+{y}")
        
        # Set window icon if logo is available
        if logo_image:
            try:
                dialog.iconphoto(False, logo_image)
            except Exception as e:
                logger.error(f"Couldn't set window icon: {e}")
        
        root.mainloop()
        
    except Exception as e:
        logger.error(f"Error in crash handler: {e}")
        traceback.print_exc()
        sys.exit()

def send_crash_report(config, exc_value, error_message, system_info, local_log_path=None):
    """Send the crash report to Discord."""
    try:
        detected_variant = detect_variant(config["game_log_path"])

        # Extract error classification info
        error_code = system_info.get("error_code", 1000)
        error_name = system_info.get("error_name", "GENERAL_APPLICATION_ERROR")
        severity = system_info.get("error_severity", "Medium")
        error_emoji = system_info.get("error_category", "❓")
        error_hash = system_info.get("error_hash", "unknown")

        # Get severity color
        severity_color = get_error_severity_color(severity)

        # Create enhanced system info without error classification (to avoid duplication)
        filtered_system_info = {k: v for k, v in system_info.items()
                               if k not in ["error_code", "error_name", "error_severity", "error_category", "error_hash"]}

        # Prepare the enhanced crash report embed
        crash_report = {
            "title": f"{error_emoji} SCKillTrac[{detected_variant}] Crash Report",
            "color": severity_color,
            "fields": [
                {
                    "name": "🔍 Error Classification",
                    "value": f"**Code:** `{error_code}`\n**Type:** `{error_name}`\n**Severity:** `{severity}`\n**Hash:** `{error_hash[:8]}...`",
                    "inline": True
                },
                {
                    "name": "📋 Error Message",
                    "value": f"```\n{str(exc_value)[:800]}\n```",
                    "inline": False
                },
                {
                    "name": "💻 System Information",
                    "value": "\n".join(f"**{k}:** {v}" for k, v in list(filtered_system_info.items())[:10])[:1000],
                    "inline": False
                },
                {
                    "name": "📜 Traceback",
                    "value": f"```python\n{error_message[:1200]}\n```",
                    "inline": False
                },
            ],
            "footer": {"text": f"SCKillTrac[{detected_variant}] Error Code: {error_code} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}
        }
        
        # Send to Discord
        response = requests.post(
            config["webhook_url"],
            data={"payload_json": json.dumps({"embeds": [crash_report]})},
            timeout=10
        )
        response.raise_for_status()
        
        # Send log files if available
        if local_log_path:
            send_file_to_discord(local_log_path, config)
        if os.path.exists(config["game_log_path"]):
            send_file_to_discord(config["game_log_path"], config)

        # Send telemetry data
        if TELEMETRY_ENABLED:
            send_telemetry_data(error_code, error_name, severity, filtered_system_info)

        # Update database with successful send
        if CRASH_ANALYTICS_ENABLED:
            try:
                conn = sqlite3.connect(CRASH_DATABASE_PATH)
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE crashes
                    SET sent_to_discord = ?
                    WHERE error_code = ? AND session_id = ?
                    ORDER BY timestamp DESC LIMIT 1
                ''', (True, error_code, SESSION_ID))
                conn.commit()
                conn.close()
            except:
                pass

    except Exception as e:
        logger.error(f"Failed to send crash report: {e}")


# === INITIALIZATION ===
def initialize_advanced_crash_system():
    """Initialize the advanced crash handling system."""
    try:
        # Initialize crash database
        if not os.path.exists(CRASH_DATABASE_PATH):
            init_crash_database()
            logger.info("Crash database initialized")

        # Start performance monitoring
        if PERFORMANCE_MONITORING:
            start_performance_monitoring()

        # Log system startup
        if CRASH_ANALYTICS_ENABLED:
            try:
                conn = sqlite3.connect(CRASH_DATABASE_PATH)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO system_diagnostics (session_id, timestamp, diagnostic_type, diagnostic_data, status)
                    VALUES (?, ?, ?, ?, ?)
                ''', (SESSION_ID, datetime.now(), "SYSTEM_STARTUP", json.dumps(get_system_info()), "SUCCESS"))
                conn.commit()
                conn.close()
            except:
                pass

        logger.info(f"Advanced crash system initialized - Session ID: {SESSION_ID}")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize advanced crash system: {e}")
        return False

# === Set up the crash handler ===
sys.excepthook = handle_crash

# Initialize the advanced crash system
initialize_advanced_crash_system()

# === TESTING FUNCTIONS ===
def test_crash_system():
    """Test the advanced crash system with a simulated error."""
    try:
        # Simulate a test error
        raise ValueError("This is a test error for the advanced crash system")
    except Exception as exc_type:
        # This will be caught by our exception hook
        pass

def get_crash_system_status():
    """Get the status of the advanced crash system."""
    status = {
        "database_initialized": os.path.exists(CRASH_DATABASE_PATH),
        "performance_monitoring": PERFORMANCE_MONITORING,
        "analytics_enabled": CRASH_ANALYTICS_ENABLED,
        "auto_recovery_enabled": AUTO_RECOVERY_ENABLED,
        "telemetry_enabled": TELEMETRY_ENABLED,
        "session_id": SESSION_ID,
        "crash_log_dir": CRASH_LOG_DIR,
        "config_dir": CONFIG_DIR
    }
    return status

if __name__ == "__main__":
    # Print system status when run directly
    print("=== SC Kill Tracker Advanced Crash System ===")
    status = get_crash_system_status()
    for key, value in status.items():
        print(f"{key}: {value}")

    # Optionally run a test
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("\nRunning crash system test...")
        test_crash_system()