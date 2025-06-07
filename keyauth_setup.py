"""
KeyAuth Setup and Configuration Tool for SC Kill Tracker
Helps configure KeyAuth integration and manage settings
"""

import os
import json
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
import requests
import hashlib
from cryptography.fernet import Fernet
import base64

class KeyAuthSetupTool:
    """Setup tool for KeyAuth configuration"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SC Kill Tracker - KeyAuth Setup")
        self.root.geometry("600x700")
        self.root.resizable(False, False)
        
        # Configuration paths
        self.config_dir = Path(os.getenv('LOCALAPPDATA')) / "Harley's Studio" / "Star Citizen Kill Tracker"
        self.config_file = self.config_dir / "keyauth_config.json"
        self.secret_file = self.config_dir / "keyauth_secret.enc"
        
        # Ensure directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.setup_ui()
        self.load_existing_config()
    
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="KeyAuth Setup for SC Kill Tracker", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Application Configuration
        app_frame = ttk.LabelFrame(main_frame, text="Application Configuration", padding="10")
        app_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(app_frame, text="App Name:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.app_name = ttk.Entry(app_frame, width=40)
        self.app_name.insert(0, "SCKillTrac")
        self.app_name.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=2)
        
        ttk.Label(app_frame, text="Owner ID:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.owner_id = ttk.Entry(app_frame, width=40)
        self.owner_id.insert(0, "EWtg9qJWO2")
        self.owner_id.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        
        ttk.Label(app_frame, text="Version:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.version = ttk.Entry(app_frame, width=40)
        self.version.insert(0, "1.0")
        self.version.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=2)
        
        ttk.Label(app_frame, text="API URL:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.api_url = ttk.Entry(app_frame, width=40)
        self.api_url.insert(0, "https://keyauth.win/api/1.3/")
        self.api_url.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=2)
        
        # Security Configuration
        security_frame = ttk.LabelFrame(main_frame, text="Security Configuration", padding="10")
        security_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(security_frame, text="Application Secret:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.app_secret = ttk.Entry(security_frame, width=40, show="*")
        self.app_secret.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=2)
        
        ttk.Label(security_frame, text="Seller Key (Admin):").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.seller_key = ttk.Entry(security_frame, width=40, show="*")
        self.seller_key.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        
        ttk.Label(security_frame, text="Discord Webhook:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.webhook_url = ttk.Entry(security_frame, width=40)
        self.webhook_url.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=2)
        
        # Protection Settings
        protection_frame = ttk.LabelFrame(main_frame, text="Protection Settings", padding="10")
        protection_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.auto_ban = tk.BooleanVar(value=True)
        ttk.Checkbutton(protection_frame, text="Auto-ban on protection violations", 
                       variable=self.auto_ban).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.hwid_tracking = tk.BooleanVar(value=True)
        ttk.Checkbutton(protection_frame, text="Enable HWID tracking", 
                       variable=self.hwid_tracking).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        self.session_monitoring = tk.BooleanVar(value=True)
        ttk.Checkbutton(protection_frame, text="Enable session monitoring", 
                       variable=self.session_monitoring).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        ttk.Label(protection_frame, text="Session Check Interval (seconds):").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.session_interval = ttk.Spinbox(protection_frame, from_=10, to=300, width=10)
        self.session_interval.set("30")
        self.session_interval.grid(row=3, column=1, sticky=tk.W, pady=2)
        
        # License Management
        license_frame = ttk.LabelFrame(main_frame, text="License Management", padding="10")
        license_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Button(license_frame, text="Generate Test Licenses", 
                  command=self.generate_test_licenses).grid(row=0, column=0, pady=5, padx=5)
        ttk.Button(license_frame, text="Open Admin Panel", 
                  command=self.open_admin_panel).grid(row=0, column=1, pady=5, padx=5)
        
        # Test Connection
        test_frame = ttk.Frame(main_frame)
        test_frame.grid(row=5, column=0, columnspan=2, pady=(0, 10))
        
        ttk.Button(test_frame, text="Test Connection", 
                  command=self.test_connection).grid(row=0, column=0, pady=5, padx=5)
        ttk.Button(test_frame, text="Validate Configuration", 
                  command=self.validate_config).grid(row=0, column=1, pady=5, padx=5)
        
        # Action Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=(20, 0))
        
        ttk.Button(button_frame, text="Save Configuration", 
                  command=self.save_config).grid(row=0, column=0, pady=5, padx=5)
        ttk.Button(button_frame, text="Load Configuration", 
                  command=self.load_config).grid(row=0, column=1, pady=5, padx=5)
        ttk.Button(button_frame, text="Reset to Defaults", 
                  command=self.reset_config).grid(row=0, column=2, pady=5, padx=5)
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, 
                                foreground="blue")
        status_label.grid(row=7, column=0, columnspan=2, pady=(10, 0))
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        app_frame.columnconfigure(1, weight=1)
        security_frame.columnconfigure(1, weight=1)
    
    def load_existing_config(self):
        """Load existing configuration if available"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
                self.app_name.delete(0, tk.END)
                self.app_name.insert(0, config.get("app_name", "SCKillTrac"))
                
                self.owner_id.delete(0, tk.END)
                self.owner_id.insert(0, config.get("owner_id", "EWtg9qJWO2"))
                
                self.version.delete(0, tk.END)
                self.version.insert(0, config.get("version", "1.0"))
                
                self.api_url.delete(0, tk.END)
                self.api_url.insert(0, config.get("api_url", "https://keyauth.win/api/1.3/"))
                
                self.webhook_url.delete(0, tk.END)
                self.webhook_url.insert(0, config.get("webhook_url", ""))
                
                self.auto_ban.set(config.get("auto_ban_on_violation", True))
                self.hwid_tracking.set(config.get("hwid_tracking", True))
                self.session_monitoring.set(config.get("session_monitoring", True))
                self.session_interval.set(str(config.get("session_check_interval", 30)))
                
                self.status_var.set("Configuration loaded")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load configuration: {e}")
    
    def save_config(self):
        """Save configuration to file"""
        try:
            config = {
                "app_name": self.app_name.get(),
                "owner_id": self.owner_id.get(),
                "version": self.version.get(),
                "api_url": self.api_url.get(),
                "webhook_url": self.webhook_url.get(),
                "auto_ban_on_violation": self.auto_ban.get(),
                "hwid_tracking": self.hwid_tracking.get(),
                "session_monitoring": self.session_monitoring.get(),
                "session_check_interval": int(self.session_interval.get())
            }
            
            # Save main config
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            
            # Save encrypted secret if provided
            if self.app_secret.get():
                try:
                    self.save_encrypted_secret(self.app_secret.get())
                except Exception as e:
                    # Fallback: save in config file (less secure but functional)
                    self.status_var.set(f"Encryption failed, saving as fallback: {e}")
                    config["app_secret"] = self.app_secret.get()
                    with open(self.config_file, 'w') as f:
                        json.dump(config, f, indent=4)
            
            self.status_var.set("Configuration saved successfully")
            messagebox.showinfo("Success", "Configuration saved successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {e}")
    
    def save_encrypted_secret(self, secret):
        """Save encrypted secret"""
        try:
            # Generate key from machine-specific data (same method as main app)
            import platform
            machine_key = hashlib.sha256(f"{platform.node()}{platform.system()}".encode()).digest()
            key = base64.urlsafe_b64encode(machine_key)

            # Encrypt secret
            fernet = Fernet(key)
            encrypted_secret = fernet.encrypt(secret.encode())

            # Save to file
            with open(self.secret_file, 'wb') as f:
                f.write(encrypted_secret)

        except Exception as e:
            raise Exception(f"Failed to encrypt secret: {e}")
    
    def test_connection(self):
        """Test connection to KeyAuth API"""
        try:
            self.status_var.set("Testing connection...")
            self.root.update()
            
            # Test basic API connectivity
            response = requests.get(self.api_url.get().replace("/api/1.3/", ""), timeout=10)
            
            if response.status_code == 200:
                self.status_var.set("Connection successful")
                messagebox.showinfo("Success", "Connection to KeyAuth API successful!")
            else:
                self.status_var.set("Connection failed")
                messagebox.showerror("Error", f"Connection failed: HTTP {response.status_code}")
                
        except Exception as e:
            self.status_var.set("Connection failed")
            messagebox.showerror("Error", f"Connection test failed: {e}")
    
    def validate_config(self):
        """Validate current configuration"""
        errors = []
        
        if not self.app_name.get():
            errors.append("App name is required")
        
        if not self.owner_id.get():
            errors.append("Owner ID is required")
        
        if not self.app_secret.get():
            errors.append("Application secret is required")
        
        if not self.version.get():
            errors.append("Version is required")
        
        try:
            int(self.session_interval.get())
        except ValueError:
            errors.append("Session interval must be a number")
        
        if errors:
            messagebox.showerror("Validation Error", "\n".join(errors))
            self.status_var.set("Configuration invalid")
        else:
            messagebox.showinfo("Validation", "Configuration is valid!")
            self.status_var.set("Configuration valid")
    
    def generate_test_licenses(self):
        """Generate test licenses"""
        if not self.seller_key.get():
            messagebox.showerror("Error", "Seller key is required to generate licenses")
            return
        
        # This would integrate with the KeyAuth admin API
        messagebox.showinfo("Info", "License generation would be implemented here")
    
    def open_admin_panel(self):
        """Open the admin panel"""
        if not self.seller_key.get():
            messagebox.showerror("Error", "Seller key is required for admin panel")
            return
        
        try:
            from keyauth_admin import KeyAuthAdminPanel
            admin_panel = KeyAuthAdminPanel(self.seller_key.get(), self.app_name.get())
            admin_panel.run()
        except ImportError:
            messagebox.showerror("Error", "Admin panel module not found")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open admin panel: {e}")
    
    def load_config(self):
        """Load configuration from file"""
        file_path = filedialog.askopenfilename(
            title="Load Configuration",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    config = json.load(f)
                
                # Update UI with loaded config
                self.load_existing_config()
                self.status_var.set("Configuration loaded from file")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load configuration: {e}")
    
    def reset_config(self):
        """Reset configuration to defaults"""
        if messagebox.askyesno("Confirm", "Reset all settings to defaults?"):
            self.app_name.delete(0, tk.END)
            self.app_name.insert(0, "SCKillTrac")
            
            self.owner_id.delete(0, tk.END)
            self.owner_id.insert(0, "EWtg9qJWO2")
            
            self.version.delete(0, tk.END)
            self.version.insert(0, "1.0")
            
            self.api_url.delete(0, tk.END)
            self.api_url.insert(0, "https://keyauth.win/api/1.3/")
            
            self.app_secret.delete(0, tk.END)
            self.seller_key.delete(0, tk.END)
            self.webhook_url.delete(0, tk.END)
            
            self.auto_ban.set(True)
            self.hwid_tracking.set(True)
            self.session_monitoring.set(True)
            self.session_interval.set("30")
            
            self.status_var.set("Configuration reset to defaults")
    
    def run(self):
        """Run the setup tool"""
        self.root.mainloop()


def main():
    """Main entry point"""
    setup_tool = KeyAuthSetupTool()
    setup_tool.run()


if __name__ == "__main__":
    main()
