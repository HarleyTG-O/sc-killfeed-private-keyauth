import subprocess
import sys
import hashlib
import time
import random
import platform
import ctypes
import os
import base64
import uuid
import socket
import threading
import json
import struct
import mmap
import gc
import weakref
import secrets
import math

# Optional imports with fallbacks
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# cpuinfo is not commonly available, so we'll use platform module instead
HAS_CPUINFO = False

try:
    import wmi
    HAS_WMI = True
except ImportError:
    HAS_WMI = False

try:
    import win32api
    HAS_WIN32API = True
except ImportError:
    HAS_WIN32API = False

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Create crash handling functions if not available
def get_system_info():
    """Get basic system information for crash reporting"""
    return {
        "platform": platform.platform(),
        "python_version": sys.version,
        "architecture": platform.architecture(),
        "processor": platform.processor(),
        "hostname": socket.gethostname()
    }

def handle_crash(exc_type, exc_value, exc_traceback):
    """Handle application crashes"""
    if exc_type is KeyboardInterrupt:
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    print(f"Critical error occurred: {exc_type.__name__}: {exc_value}")
    sys.exit(1)

class AdvancedProtection:
    _instance = None
    _lock = threading.RLock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
            return cls._instance

    def __init__(self, app_name="SCKillTrac[Global]", check_interval=30, webhook_url=None):
        if hasattr(self, '_initialized'):
            return

        self.app_name = app_name
        self.check_interval = check_interval + random.randint(-5, 5)  # Randomize interval
        self.webhook_url = webhook_url
        self.critical_files = []
        self.original_checksums = {}
        self.debug_attempts = 0
        self.last_check_time = 0
        self.hardware_id = self._generate_hardware_id()
        self.execution_path = os.path.dirname(os.path.abspath(sys.argv[0]))
        self.protection_active = False
        self.fernet_key = self._generate_fernet_key()
        self._decoy_data = self._generate_decoy_data()
        self._anti_tamper_checks = []
        self._memory_canaries = {}
        self._process_integrity_hash = None
        self._vm_artifacts = self._detect_vm_artifacts()
        self._sandbox_artifacts = self._detect_sandbox_artifacts()
        self._initialize_protection()
        self._initialized = True
        self._send_webhook_message("Protection initialized", "Advanced protection system activated", 0x00FF00)

    @staticmethod
    def integrate_protection():
        """Public interface for protection system"""
        if 'protection_system' not in globals():
            globals()['protection_system'] = AdvancedProtection()
        return globals()['protection_system']

    @staticmethod
    def get_protection():
        """Get singleton instance"""
        return AdvancedProtection()

    def _generate_decoy_data(self):
        """Generate decoy data to confuse attackers"""
        decoys = {}
        for i in range(10):
            decoys[f"fake_key_{i}"] = secrets.token_hex(32)
            decoys[f"fake_hash_{i}"] = hashlib.sha256(secrets.token_bytes(64)).hexdigest()
        return decoys

    def _detect_vm_artifacts(self):
        """Detect virtual machine artifacts"""
        vm_indicators = []

        try:
            # Check for VM-specific registry keys (Windows)
            if platform.system() == "Windows" and HAS_WINREG:
                vm_keys = [
                    r"SYSTEM\CurrentControlSet\Services\VBoxService",
                    r"SYSTEM\CurrentControlSet\Services\VMTools",
                    r"SOFTWARE\VMware, Inc.\VMware Tools"
                ]
                for key_path in vm_keys:
                    try:
                        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                        vm_indicators.append(f"VM registry key: {key_path}")
                    except FileNotFoundError:
                        pass
        except Exception:
            pass

        return vm_indicators

    def _detect_sandbox_artifacts(self):
        """Detect sandbox environment artifacts"""
        sandbox_indicators = []

        # Check for common sandbox usernames
        username = os.getenv('USERNAME', '').lower()
        sandbox_users = ['sandbox', 'malware', 'virus', 'sample', 'test']
        if any(user in username for user in sandbox_users):
            sandbox_indicators.append(f"Sandbox username: {username}")

        # Check for low system resources (common in sandboxes)
        if HAS_PSUTIL:
            try:
                if psutil.virtual_memory().total < 2 * 1024 * 1024 * 1024:  # Less than 2GB RAM
                    sandbox_indicators.append("Low memory (possible sandbox)")
            except Exception:
                pass

        return sandbox_indicators

    def _generate_fernet_key(self):
        # Use hardware ID as part of key derivation
        hardware_bytes = self.hardware_id.encode() if isinstance(self.hardware_id, str) else self.hardware_id
        salt = hashlib.sha256(hardware_bytes + b"protection_salt").digest()[:16]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=500000,  # Increased iterations
        )
        key = base64.urlsafe_b64encode(kdf.derive(hardware_bytes))
        return key
    
    def _initialize_protection(self):
        try:
            self._register_critical_files()
            self._calculate_checksums()
            self._setup_memory_canaries()
            self._calculate_process_integrity()
            self.protection_active = True
            self._obfuscate_memory()
            self._setup_anti_tamper_checks()
        except Exception as e:
            self._send_webhook_message("Initialization Error", f"Failed to initialize protection: {str(e)}", 0xFF0000)

    def _setup_memory_canaries(self):
        """Setup memory canaries to detect tampering"""
        for i in range(5):
            canary_value = secrets.token_hex(16)
            self._memory_canaries[f"canary_{i}"] = canary_value

    def _calculate_process_integrity(self):
        """Calculate integrity hash of current process"""
        try:
            with open(sys.executable, 'rb') as f:
                process_data = f.read()
            self._process_integrity_hash = hashlib.sha3_256(process_data).hexdigest()
        except Exception:
            self._process_integrity_hash = "unknown"

    def _setup_anti_tamper_checks(self):
        """Setup various anti-tamper mechanisms"""
        # Add function pointer checks
        self._anti_tamper_checks.extend([
            self._check_function_integrity,
            self._check_memory_canaries,
            self._check_process_integrity
        ])

    def _check_function_integrity(self):
        """Check if critical functions have been tampered with"""
        try:
            # Check if our methods still exist and have expected properties
            critical_methods = [
                '_detect_debugger', '_check_file_integrity',
                '_encrypt_string', '_decrypt_string'
            ]
            for method_name in critical_methods:
                if not hasattr(self, method_name):
                    return False
                method = getattr(self, method_name)
                if not callable(method):
                    return False
            return True
        except Exception:
            return False

    def _check_memory_canaries(self):
        """Check if memory canaries are intact"""
        try:
            for canary_name, expected_value in self._memory_canaries.items():
                if canary_name not in self._memory_canaries:
                    return False
                if self._memory_canaries[canary_name] != expected_value:
                    return False
            return True
        except Exception:
            return False

    def _check_process_integrity(self):
        """Check if process integrity is maintained"""
        try:
            if self._process_integrity_hash == "unknown":
                return True  # Skip check if we couldn't calculate initially

            with open(sys.executable, 'rb') as f:
                current_data = f.read()
            current_hash = hashlib.sha3_256(current_data).hexdigest()
            return current_hash == self._process_integrity_hash
        except Exception:
            return False

    def _obfuscate_memory(self):
        """Obfuscate sensitive data in memory with improved encryption"""
        if isinstance(self.hardware_id, str) and len(self.hardware_id) <= 32:
            self.hardware_id = self._encrypt_string(self.hardware_id, level=4)

        # Only encrypt checksums if they're not already encrypted
        if not hasattr(self, '_checksums_encrypted') or not self._checksums_encrypted:
            encrypted_checksums = {}
            for file_path, checksum in self.original_checksums.items():
                try:
                    encrypted_checksums[self._encrypt_string(file_path, level=2)] = self._encrypt_string(checksum, level=3)
                except Exception:
                    # If encryption fails, store as-is
                    encrypted_checksums[file_path] = checksum
            self.original_checksums = encrypted_checksums
            self._checksums_encrypted = True

        self._memory_obfuscated = True

    def _deobfuscate_memory(self):
        """Deobfuscate sensitive data when needed"""
        # Only deobfuscate if data is actually encrypted
        if hasattr(self, '_memory_obfuscated') and self._memory_obfuscated:
            if isinstance(self.hardware_id, str) and len(self.hardware_id) > 32:
                try:
                    self.hardware_id = self._decrypt_string(self.hardware_id, level=4)
                except Exception:
                    # If decryption fails, regenerate hardware ID
                    self.hardware_id = self._generate_hardware_id()

            # Decrypt checksums only if they appear to be encrypted
            if hasattr(self, '_checksums_encrypted') and self._checksums_encrypted:
                decrypted_checksums = {}
                for enc_path, enc_checksum in self.original_checksums.items():
                    try:
                        # Check if the path looks encrypted (longer than normal path)
                        if len(enc_path) > 200:  # Encrypted paths are much longer
                            file_path = self._decrypt_string(enc_path, level=2)
                            checksum = self._decrypt_string(enc_checksum, level=3)
                            decrypted_checksums[file_path] = checksum
                        else:
                            # Path is not encrypted, use as-is
                            decrypted_checksums[enc_path] = enc_checksum
                    except Exception:
                        # If decryption fails, skip this entry
                        continue
                self.original_checksums = decrypted_checksums
                self._checksums_encrypted = False

            self._memory_obfuscated = False

    def _generate_hardware_id(self):
        """Generate a more robust hardware fingerprint"""
        try:
            components = []

            # CPU information - use platform module for better compatibility
            cpu_info = platform.processor()
            if not cpu_info:  # Fallback if processor() returns empty
                cpu_info = platform.machine()
            components.append(cpu_info)

            # System information
            components.extend([
                str(uuid.getnode()),  # MAC address
                platform.node(),      # Hostname
                platform.system(),    # OS
                platform.release(),   # OS version
            ])

            # Disk serial
            disk_serial = self._get_disk_serial()
            components.append(disk_serial)

            # Memory information
            if HAS_PSUTIL:
                try:
                    components.append(str(psutil.virtual_memory().total))
                except Exception:
                    pass

            # Create multiple hash layers for better security
            fingerprint = ":".join(filter(None, components))
            hash1 = hashlib.sha3_256(fingerprint.encode()).hexdigest()
            hash2 = hashlib.blake2b(hash1.encode(), digest_size=32).hexdigest()

            return hash2[:32]
        except Exception as e:
            self._send_webhook_message("Hardware ID Error", f"Failed to generate hardware ID: {str(e)}", 0xFFA500)
            # Fallback to a more basic but still unique identifier
            fallback = f"{socket.gethostname()}:{platform.system()}:{time.time()}"
            return hashlib.sha256(fallback.encode()).hexdigest()[:32]

    def _get_disk_serial(self):
        """Get disk serial number with multiple fallback methods"""
        try:
            if platform.system() == "Windows":
                if HAS_WMI:
                    try:
                        c = wmi.WMI()
                        for disk in c.Win32_PhysicalMedia():
                            if disk.SerialNumber:
                                return disk.SerialNumber.strip()
                    except Exception:
                        pass

                if HAS_WIN32API:
                    try:
                        return str(win32api.GetVolumeInformation("C:\\")[1])
                    except Exception:
                        pass

                try:
                    # Command line fallback
                    result = subprocess.check_output("wmic diskdrive get serialnumber", shell=True, text=True)
                    lines = result.strip().split('\n')
                    for line in lines[1:]:  # Skip header
                        serial = line.strip()
                        if serial and serial != "SerialNumber":
                            return serial
                except Exception:
                    pass

            elif platform.system() == "Linux":
                try:
                    with open('/etc/machine-id', 'r') as f:
                        return f.read().strip()
                except FileNotFoundError:
                    try:
                        result = subprocess.check_output("lsblk -o SERIAL", shell=True, text=True)
                        lines = result.strip().split('\n')
                        for line in lines[1:]:  # Skip header
                            serial = line.strip()
                            if serial and serial != "SERIAL":
                                return serial
                    except Exception:
                        pass

            elif platform.system() == "Darwin":
                try:
                    result = subprocess.check_output("ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID", shell=True, text=True)
                    return result.split('=')[-1].strip().strip('"')
                except Exception:
                    pass

            # Final fallback
            return str(hash(str(os.statvfs('/').f_fsid if hasattr(os, 'statvfs') else os.urandom(8))))

        except Exception:
            return secrets.token_hex(8)

    def _register_critical_files(self):
        """Register critical files for integrity monitoring"""
        # Always include the main executable
        main_exe = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
        if os.path.exists(main_exe):
            self.critical_files.append(main_exe)

        # If not frozen, include Python files
        if not getattr(sys, 'frozen', False):
            # Include current script
            if sys.argv[0] and os.path.exists(sys.argv[0]):
                self.critical_files.append(os.path.abspath(sys.argv[0]))

            # Include files in execution directory
            try:
                for root, _, files in os.walk(self.execution_path):
                    for file in files:
                        if file.endswith(('.py', '.pyc', '.pyd', '.dll', '.so', '.exe')):
                            full_path = os.path.join(root, file)
                            if os.path.exists(full_path) and full_path not in self.critical_files:
                                self.critical_files.append(full_path)
            except Exception as e:
                self._send_webhook_message("File Registration Error", f"Error registering files: {str(e)}", 0xFFA500)

        # Include system-critical files that might be targeted
        system_files = []
        if platform.system() == "Windows":
            system_files.extend([
                os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32', 'ntdll.dll'),
                os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32', 'kernel32.dll')
            ])

        for sys_file in system_files:
            if os.path.exists(sys_file):
                self.critical_files.append(sys_file)

        # Remove duplicates
        self.critical_files = list(set(self.critical_files))

    def _calculate_checksums(self):
        """Calculate checksums for critical files with enhanced security"""
        for file_path in self.critical_files:
            try:
                if os.path.exists(file_path) and os.path.isfile(file_path):
                    # Use multiple hash algorithms for better security
                    with open(file_path, 'rb') as f:
                        file_data = f.read()

                    # Create composite hash
                    sha3_hash = hashlib.sha3_256(file_data).hexdigest()
                    blake2_hash = hashlib.blake2b(file_data, digest_size=32).hexdigest()
                    composite_hash = hashlib.sha256((sha3_hash + blake2_hash).encode()).hexdigest()

                    self.original_checksums[file_path] = composite_hash

            except PermissionError:
                # Skip files we can't read due to permissions
                continue
            except Exception as e:
                self._send_webhook_message("Checksum Error", f"Failed to calculate checksum for {file_path}: {str(e)}", 0xFFA500)
                continue

    def _check_file_integrity(self):
        """Check integrity of critical files with improved error handling"""
        if not self.protection_active:
            return True

        # Temporarily deobfuscate memory for checking
        original_checksums_backup = self.original_checksums.copy()

        try:
            self._deobfuscate_memory()
        except Exception:
            # If deobfuscation fails, use backup and continue
            self.original_checksums = original_checksums_backup

        integrity_ok = True

        for file_path, original_checksum in self.original_checksums.items():
            try:
                if os.path.exists(file_path) and os.path.isfile(file_path):
                    with open(file_path, 'rb') as f:
                        current_data = f.read()

                    # Use the same composite hash as in _calculate_checksums
                    sha3_hash = hashlib.sha3_256(current_data).hexdigest()
                    blake2_hash = hashlib.blake2b(current_data, digest_size=32).hexdigest()
                    current_checksum = hashlib.sha256((sha3_hash + blake2_hash).encode()).hexdigest()

                    if current_checksum != original_checksum:
                        self._send_webhook_message("Integrity Violation", f"File modification detected: {file_path}", 0xFF0000)
                        integrity_ok = False

            except PermissionError:
                # Skip files we can't read due to permissions
                continue
            except Exception as e:
                # Only log critical errors, not decryption issues
                if "decrypt" not in str(e).lower():
                    self._send_webhook_message("Integrity Check Error", f"Failed to verify integrity for {file_path}: {str(e)}", 0xFF0000)
                    integrity_ok = False

        # Re-obfuscate memory
        try:
            self._obfuscate_memory()
        except Exception:
            # If re-obfuscation fails, continue anyway
            pass

        return integrity_ok

    def _detect_debugger(self):
        """Enhanced debugger detection with multiple techniques"""
        if not self.protection_active:
            return False

        debugger_detected = False
        detection_methods = []

        # Advanced timing checks with randomization
        try:
            # Multiple timing samples to avoid false positives
            timing_samples = []
            for _ in range(3):
                start_time = time.perf_counter()
                result = self._timing_detection_calculation()
                end_time = time.perf_counter()
                timing_samples.append(end_time - start_time)

                # Add some noise to make timing analysis harder
                time.sleep(random.uniform(0.001, 0.005))

            avg_time = sum(timing_samples) / len(timing_samples)
            # Dynamic threshold based on system performance
            threshold = 0.1 if any(t > 0.05 for t in timing_samples) else 0.05

            if avg_time > threshold:
                detection_methods.append(f"Timing anomaly (avg: {avg_time:.4f}s)")
                debugger_detected = True

        except Exception as e:
            self._send_webhook_message("Timing Check Error", f"Timing detection failed: {str(e)}", 0xFFA500)

        # Enhanced Windows-specific checks
        if platform.system() == "Windows":
            try:
                kernel32 = ctypes.windll.kernel32
                ntdll = ctypes.windll.ntdll

                # Multiple debugger presence checks
                try:
                    if kernel32.IsDebuggerPresent() != 0:
                        detection_methods.append("IsDebuggerPresent")
                        debugger_detected = True
                except Exception as e:
                    self._send_webhook_message("Debugger Check Error", f"IsDebuggerPresent failed: {str(e)}", 0xFFA500)

                # Check remote debugger
                try:
                    debug_flag = ctypes.c_int(0)
                    kernel32.CheckRemoteDebuggerPresent(
                        kernel32.GetCurrentProcess(),
                        ctypes.byref(debug_flag))
                    if debug_flag.value != 0:
                        detection_methods.append("RemoteDebuggerPresent")
                        debugger_detected = True
                except Exception as e:
                    self._send_webhook_message("Debugger Check Error", f"Remote debugger check failed: {str(e)}", 0xFFA500)

                # Check PEB flags (Process Environment Block)
                try:
                    peb_base = ctypes.c_void_p()
                    ntdll.NtQueryInformationProcess(
                        kernel32.GetCurrentProcess(),
                        0,  # ProcessBasicInformation
                        ctypes.byref(peb_base),
                        ctypes.sizeof(peb_base),
                        None
                    )

                    if peb_base.value:
                        # Read BeingDebugged flag from PEB
                        being_debugged = ctypes.c_ubyte()
                        kernel32.ReadProcessMemory(
                            kernel32.GetCurrentProcess(),
                            peb_base.value + 2,  # Offset to BeingDebugged flag
                            ctypes.byref(being_debugged),
                            1,
                            None
                        )
                        if being_debugged.value != 0:
                            detection_methods.append("PEB BeingDebugged flag")
                            debugger_detected = True
                except Exception:
                    pass  # PEB checks can be complex and may fail on some systems

                # Enhanced process detection
                try:
                    debugger_processes = [
                        "ollydbg.exe", "idaq.exe", "idaq64.exe", "windbg.exe",
                        "x32dbg.exe", "x64dbg.exe", "immunitydebugger.exe",
                        "devenv.exe", "procmon.exe", "wireshark.exe", "fiddler.exe",
                        "processhacker.exe", "cheatengine.exe", "ida.exe", "ida64.exe",
                        "ghidra.exe", "radare2.exe", "dnspy.exe", "reflexil.exe"
                    ]

                    # Check for analysis tools
                    analysis_tools = [
                        "procexp.exe", "procexp64.exe", "autoruns.exe", "autorunsc.exe",
                        "tcpview.exe", "portmon.exe", "filemon.exe", "regmon.exe"
                    ]

                    all_suspicious = debugger_processes + analysis_tools

                    if HAS_PSUTIL:
                        try:
                            running_processes = [proc.info['name'].lower() for proc in psutil.process_iter(['name'])]

                            for suspicious_proc in all_suspicious:
                                if suspicious_proc.lower() in running_processes:
                                    detection_methods.append(f"Suspicious process: {suspicious_proc}")
                                    debugger_detected = True

                            # Check for processes with suspicious command lines
                            for proc in psutil.process_iter(['name', 'cmdline']):
                                try:
                                    cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ''
                                    if any(keyword in cmdline for keyword in ['debug', 'trace', 'inject', 'hook']):
                                        detection_methods.append(f"Suspicious cmdline: {proc.info['name']}")
                                        debugger_detected = True
                                except (psutil.AccessDenied, psutil.NoSuchProcess):
                                    continue
                        except Exception:
                            pass
                    else:
                        # Fallback to tasklist if psutil not available
                        try:
                            result = subprocess.check_output("tasklist", shell=True, text=True)
                            for suspicious_proc in all_suspicious:
                                if suspicious_proc.lower() in result.lower():
                                    detection_methods.append(f"Suspicious process (tasklist): {suspicious_proc}")
                                    debugger_detected = True
                        except Exception:
                            pass

                except Exception as e:
                    self._send_webhook_message("Process Check Error", f"Process check failed: {str(e)}", 0xFFA500)

            except Exception as e:
                self._send_webhook_message("Windows Debug Check Error", f"Windows debug detection failed: {str(e)}", 0xFFA500)

        # Linux specific checks
        elif platform.system() == "Linux":
            try:
                with open(f"/proc/{os.getpid()}/status", "r") as f:
                    content = f.read()
                    if "TracerPid:" in content:
                        tracer_pid = int(content.split("TracerPid:")[1].split()[0])
                        if tracer_pid != 0:
                            detection_methods.append(f"TracerPid detected: {tracer_pid}")
                            debugger_detected = True
            except FileNotFoundError:
                pass  # /proc filesystem not available
            except Exception as e:
                self._send_webhook_message("Linux Debug Check Error", f"Linux debug detection failed: {str(e)}", 0xFFA500)

        # Check debug environment variables
        try:
            debug_env_vars = ["PYTHONDEBUG", "PYTHONINSPECT", "PYTHONBREAKPOINT"]
            for var in debug_env_vars:
                if var in os.environ and os.environ[var] != "0":
                    detection_methods.append(f"Debug env var: {var}")
                    debugger_detected = True
        except Exception as e:
            self._send_webhook_message("Env Var Check Error", f"Environment variable check failed: {str(e)}", 0xFFA500)

        if debugger_detected:
            self._send_webhook_message("Debugger Detected", 
                                     f"Debugger detected via: {', '.join(detection_methods)}", 
                                     0xFF0000)

        return debugger_detected

    def _detect_vm_environment(self):
        """Detect virtual machine environment"""
        if not self.protection_active:
            return False

        vm_detected = False
        vm_indicators = []

        # Check previously detected artifacts
        if self._vm_artifacts:
            vm_indicators.extend(self._vm_artifacts)
            vm_detected = True

        # Additional runtime VM checks
        try:
            # Check for VM-specific hardware
            if platform.system() == "Windows" and HAS_WMI:
                try:
                    c = wmi.WMI()

                    # Check BIOS
                    for bios in c.Win32_BIOS():
                        if any(vm_vendor in bios.Manufacturer.lower() for vm_vendor in
                               ['vmware', 'virtualbox', 'qemu', 'xen', 'microsoft corporation']):
                            vm_indicators.append(f"VM BIOS: {bios.Manufacturer}")
                            vm_detected = True

                    # Check computer system
                    for cs in c.Win32_ComputerSystem():
                        if any(vm_vendor in cs.Manufacturer.lower() for vm_vendor in
                               ['vmware', 'virtualbox', 'qemu', 'xen', 'microsoft corporation']):
                            vm_indicators.append(f"VM System: {cs.Manufacturer}")
                            vm_detected = True

                except Exception:
                    pass

            # Check for VM-specific files
            vm_files = [
                r"C:\windows\system32\drivers\vmmouse.sys",
                r"C:\windows\system32\drivers\vmhgfs.sys",
                r"C:\windows\system32\drivers\VBoxMouse.sys",
                r"C:\windows\system32\drivers\VBoxGuest.sys",
                "/usr/bin/vmware-toolbox-cmd",
                "/usr/bin/VBoxControl"
            ]

            for vm_file in vm_files:
                if os.path.exists(vm_file):
                    vm_indicators.append(f"VM file: {vm_file}")
                    vm_detected = True

        except Exception as e:
            self._send_webhook_message("VM Detection Error", f"VM detection failed: {str(e)}", 0xFFA500)

        if vm_detected:
            self._send_webhook_message("VM Environment Detected",
                                     f"Virtual machine detected: {', '.join(vm_indicators)}",
                                     0xFFFF00)

        return vm_detected

    def _timing_detection_calculation(self):
        """More complex timing calculation to detect debugging"""
        total = 0
        # Randomize the calculation to make it harder to predict
        iterations = random.randint(15000, 25000)
        multiplier = random.randint(7, 13)

        for i in range(iterations):
            # More complex calculation
            total += (i * multiplier) % 17
            if i % 1000 == 0:
                # Add some floating point operations
                total += int(math.sqrt(i) * math.sin(i / 100))

        return total

    def _encrypt_string(self, text, level=1):
        """Enhanced encryption with multiple layers and better security"""
        if not text:
            return ""

        try:
            if level == 1:
                # Simple base64 encoding
                return base64.b64encode(text.encode('utf-8')).decode('ascii')

            elif level == 2:
                # XOR with hardware-derived key
                if isinstance(self.hardware_id, str):
                    key = self.hardware_id
                else:
                    key = self._decrypt_string(self.hardware_id, level=3)

                # Create a longer key by repeating and hashing
                extended_key = hashlib.sha256((key * 10).encode()).digest()

                text_bytes = text.encode('utf-8')
                xored = bytes(b ^ extended_key[i % len(extended_key)] for i, b in enumerate(text_bytes))
                return base64.b64encode(xored).decode('ascii')

            elif level == 3:
                # Fernet encryption
                f = Fernet(self.fernet_key)
                return f.encrypt(text.encode('utf-8')).decode('ascii')

            elif level == 4:
                # Multi-layer encryption
                if isinstance(self.hardware_id, str):
                    key_source = self.hardware_id
                else:
                    key_source = self._decrypt_string(self.hardware_id, level=3)

                # Layer 1: AES encryption
                key = hashlib.sha256(key_source.encode()).digest()
                iv = secrets.token_bytes(16)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()

                # Pad the text
                text_bytes = text.encode('utf-8')
                padding_length = 16 - (len(text_bytes) % 16)
                padded_text = text_bytes + bytes([padding_length] * padding_length)

                encrypted = encryptor.update(padded_text) + encryptor.finalize()

                # Layer 2: XOR with time-based key
                time_key = hashlib.sha256(str(int(time.time() // 3600)).encode()).digest()
                final_encrypted = bytes(b ^ time_key[i % len(time_key)] for i, b in enumerate(iv + encrypted))

                return base64.b64encode(final_encrypted).decode('ascii')

            else:
                # Fallback to level 3
                return self._encrypt_string(text, level=3)

        except Exception as e:
            self._send_webhook_message("Encryption Error", f"Failed to encrypt string (level {level}): {str(e)}", 0xFF0000)
            return text

    def _decrypt_string(self, encrypted_text, level=1):
        """Enhanced decryption corresponding to encryption levels"""
        if not encrypted_text:
            return ""

        try:
            if level == 1:
                # Simple base64 decoding
                return base64.b64decode(encrypted_text.encode('ascii')).decode('utf-8')

            elif level == 2:
                # XOR decryption
                if isinstance(self.hardware_id, str):
                    key = self.hardware_id
                else:
                    key = self._decrypt_string(self.hardware_id, level=3)

                extended_key = hashlib.sha256((key * 10).encode()).digest()

                encrypted_bytes = base64.b64decode(encrypted_text.encode('ascii'))
                decrypted = bytes(b ^ extended_key[i % len(extended_key)] for i, b in enumerate(encrypted_bytes))
                return decrypted.decode('utf-8')

            elif level == 3:
                # Fernet decryption
                f = Fernet(self.fernet_key)
                return f.decrypt(encrypted_text.encode('ascii')).decode('utf-8')

            elif level == 4:
                # Multi-layer decryption
                if isinstance(self.hardware_id, str):
                    key_source = self.hardware_id
                else:
                    key_source = self._decrypt_string(self.hardware_id, level=3)

                encrypted_data = base64.b64decode(encrypted_text.encode('ascii'))

                # Layer 1: Reverse time-based XOR
                time_key = hashlib.sha256(str(int(time.time() // 3600)).encode()).digest()
                xor_reversed = bytes(b ^ time_key[i % len(time_key)] for i, b in enumerate(encrypted_data))

                # Extract IV and encrypted data
                iv = xor_reversed[:16]
                encrypted = xor_reversed[16:]

                # Layer 2: AES decryption
                key = hashlib.sha256(key_source.encode()).digest()
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()

                padded_text = decryptor.update(encrypted) + decryptor.finalize()

                # Remove padding
                padding_length = padded_text[-1]
                text_bytes = padded_text[:-padding_length]

                return text_bytes.decode('utf-8')

            else:
                # Fallback to level 3
                return self._decrypt_string(encrypted_text, level=3)

        except Exception as e:
            self._send_webhook_message("Decryption Error", f"Failed to decrypt string (level {level}): {str(e)}", 0xFF0000)
            return encrypted_text

    def _send_webhook_message(self, title, description, color):
        """Send webhook message if requests is available"""
        if not self.webhook_url or not HAS_REQUESTS:
            # Fallback to local logging if no webhook or requests available
            print(f"[{title}] {description}")
            return

        try:
            embed = {
                "title": title,
                "description": description,
                "color": color,
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {
                    "text": self.app_name
                },
                "fields": [
                    {
                        "name": "Hardware ID",
                        "value": f"`{self._decrypt_string(self.hardware_id, level=3)[:8]}...`",
                        "inline": True
                    },
                    {
                        "name": "System",
                        "value": f"{platform.system()} {platform.release()}",
                        "inline": True
                    },
                    {
                        "name": "Process",
                        "value": os.path.basename(sys.executable),
                        "inline": True
                    }
                ]
            }

            data = {
                "embeds": [embed],
                "username": "Protection System",
                "avatar_url": "https://i.imgur.com/4M34hi2.png"
            }

            headers = {'Content-Type': 'application/json'}
            requests.post(self.webhook_url, data=json.dumps(data), headers=headers, timeout=5)
        except Exception as e:
            print(f"Failed to send webhook: {str(e)}")

    def _handle_protection_violation(self, violation_type):
        """Enhanced protection violation handling"""
        if violation_type == "debugger":
            self.debug_attempts += 1

            # Escalating response based on attempts
            if self.debug_attempts >= 5:
                self._send_webhook_message("Critical Protection Violation",
                                         f"Multiple debugger detection attempts ({self.debug_attempts})",
                                         0xFF0000)
                self._trigger_protection_response("critical")
            elif self.debug_attempts >= 3:
                self._send_webhook_message("Protection Warning",
                                         f"Repeated debugger detection ({self.debug_attempts})",
                                         0xFFA500)
                self._trigger_protection_response("warning")
                # Add delay to slow down analysis
                time.sleep(random.uniform(2.0, 5.0))
            else:
                # Subtle delay for first few attempts
                time.sleep(random.uniform(0.5, 2.0))

        elif violation_type == "integrity":
            self._send_webhook_message("Critical Protection Violation",
                                     "File integrity violation detected",
                                     0xFF0000)
            self._trigger_protection_response("critical")

        elif violation_type == "vm":
            self._send_webhook_message("Environment Warning",
                                      "Virtual machine environment detected",
                                      0xFFFF00)
            self._trigger_protection_response("warning")

        elif violation_type == "sandbox":
            self._send_webhook_message("Environment Warning",
                                      "Sandbox environment detected",
                                      0xFFFF00)
            self._trigger_protection_response("warning")

        elif violation_type == "tamper":
            self._send_webhook_message("Critical Protection Violation",
                                     "Anti-tamper check failed - code modification detected",
                                     0xFF0000)
            self._trigger_protection_response("critical")

    def _trigger_protection_response(self, severity):
        """Enhanced protection response with better obfuscation"""
        if severity == "critical":
            # More realistic error messages
            error_messages = [
                "Fatal error: Application data corrupted. Please reinstall the application.",
                "System compatibility check failed. Error code: 0x80070005",
                "Required system libraries are missing or corrupted.",
                "Application integrity verification failed. Please contact support.",
                "Critical system error detected. Application cannot continue.",
                "Memory allocation failed. Insufficient system resources.",
                "Configuration file is corrupted or missing.",
                "License verification failed. Please check your installation."
            ]

            # Display error and perform cleanup
            selected_error = random.choice(error_messages)
            print(f"\nERROR: {selected_error}")

            # Add some delay to make it look like a real error
            time.sleep(random.uniform(1.0, 3.0))

            self._secure_cleanup()

            # Exit with different codes to make analysis harder
            exit_codes = [1, 3, 5, 7, 11]
            sys.exit(random.choice(exit_codes))

        elif severity == "warning":
            # Introduce random delays and performance degradation
            delay = random.uniform(2, 8)
            time.sleep(delay)

            # Occasionally trigger false positive messages
            if random.random() < 0.3:
                warning_messages = [
                    "Performance optimization in progress...",
                    "Updating configuration settings...",
                    "Checking for updates...",
                    "Validating system compatibility..."
                ]
                print(random.choice(warning_messages))
                time.sleep(random.uniform(1, 3))

    def _secure_cleanup(self):
        try:
            # Overwrite sensitive data
            self.hardware_id = os.urandom(32).hex()
            self.original_checksums = {k: os.urandom(64).hex() for k in self.original_checksums}
            self.critical_files = [os.urandom(16).hex() for _ in range(10)]

            # Fill memory with junk data
            junk_data = []
            for _ in range(10):
                junk_data.append(bytearray(os.urandom(1024 * 1024)))

            # Clear encryption key
            self.fernet_key = os.urandom(32)
        except Exception as e:
            self._send_webhook_message("Cleanup Error", f"Failed secure cleanup: {str(e)}", 0xFF0000)

    def check_environment(self):
        """Enhanced environment checking with anti-tamper validation"""
        current_time = time.time()

        # Randomize check intervals to make timing attacks harder
        actual_interval = self.check_interval + random.uniform(-3, 3)
        if current_time - self.last_check_time < actual_interval:
            return True

        self.last_check_time = current_time

        # Run anti-tamper checks first
        for check_func in self._anti_tamper_checks:
            try:
                if not check_func():
                    self._handle_protection_violation("tamper")
                    return False
            except Exception as e:
                self._send_webhook_message("Anti-Tamper Error", f"Check failed: {str(e)}", 0xFF0000)
                self._handle_protection_violation("tamper")
                return False

        # Check for debugger with enhanced detection
        if self._detect_debugger():
            self._handle_protection_violation("debugger")
            return False

        # Verify file integrity
        if not self._check_file_integrity():
            self._handle_protection_violation("integrity")
            return False

        # Check for VM/sandbox environment
        if self._detect_vm_environment():
            self._handle_protection_violation("vm")

        # Check for sandbox artifacts
        if self._sandbox_artifacts:
            self._handle_protection_violation("sandbox")

        # Send periodic heartbeat with reduced frequency
        if random.random() < 0.05:  # 5% chance to send heartbeat
            self._send_webhook_message("Heartbeat", "Advanced protection system active", 0x00FF00)

        return True
    
    def start_protection_thread(self):
        """Start enhanced protection monitoring thread"""
        if not self.protection_active:
            return

        def protection_monitor():
            consecutive_errors = 0
            max_errors = 5

            while True:
                try:
                    # Randomize thread execution timing
                    pre_delay = random.uniform(0.1, 0.5)
                    time.sleep(pre_delay)

                    # Run protection checks
                    if not self.check_environment():
                        # If check fails, the violation handler will deal with it
                        pass

                    # Reset error counter on successful check
                    consecutive_errors = 0

                    # Variable sleep time to make timing analysis harder
                    base_sleep = self.check_interval
                    jitter = random.uniform(-8, 8)
                    sleep_time = max(5, base_sleep + jitter)  # Minimum 5 seconds

                    time.sleep(sleep_time)

                except Exception as e:
                    consecutive_errors += 1
                    self._send_webhook_message("Monitor Error",
                                             f"Protection thread error ({consecutive_errors}/{max_errors}): {str(e)}",
                                             0xFF0000)

                    if consecutive_errors >= max_errors:
                        self._send_webhook_message("Critical Monitor Error",
                                                 "Protection thread failed repeatedly - potential tampering",
                                                 0xFF0000)
                        self._trigger_protection_response("critical")
                        break

                    # Exponential backoff on errors
                    error_sleep = min(60, 5 * (2 ** consecutive_errors))
                    time.sleep(error_sleep)

        # Create thread with random name to make detection harder
        thread_names = ["SystemMonitor", "ConfigWatcher", "UpdateChecker", "HealthMonitor", "ServiceWatcher"]
        thread_name = random.choice(thread_names)

        protection_thread = threading.Thread(target=protection_monitor, daemon=True, name=thread_name)
        protection_thread.start()

        self._send_webhook_message("Protection Active",
                                 f"Advanced protection monitoring activated (Thread: {thread_name})",
                                 0x00FF00)

# Enhanced factory function for easier integration
def create_protection_system(app_name="SCKillTrac[Global]", webhook_url=None, check_interval=30):
    """Factory function to create and initialize protection system"""
    return AdvancedProtection(app_name=app_name, webhook_url=webhook_url, check_interval=check_interval)

# Convenience function for quick integration
def enable_protection(webhook_url=None):
    """Quick setup function for basic protection"""
    protection = AdvancedProtection(webhook_url=webhook_url)
    protection.start_protection_thread()
    return protection

if __name__ == "__main__":
    sys.excepthook = handle_crash