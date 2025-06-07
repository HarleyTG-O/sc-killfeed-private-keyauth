"""
KeyAuth Authentication Dialogs for SC Kill Tracker
Modern Qt-based authentication interface with full KeyAuth integration
"""

import sys
import os
from PySide6.QtWidgets import (
    QApplication, QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QTabWidget, QWidget, QMessageBox, QProgressBar,
    QTextEdit, QCheckBox, QFrame, QGridLayout, QSpacerItem, QSizePolicy
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QPixmap, QPalette, QColor, QIcon
import logging
from typing import Optional, Dict, Any
from keyauth_integration import get_keyauth_manager, initialize_keyauth


class AuthWorker(QThread):
    """Background worker for authentication operations"""
    
    finished = Signal(dict)
    error = Signal(str)
    progress = Signal(str)
    
    def __init__(self, auth_type: str, **kwargs):
        super().__init__()
        self.auth_type = auth_type
        self.auth_data = kwargs
    
    def run(self):
        """Run authentication in background"""
        try:
            manager = get_keyauth_manager()
            if not manager:
                self.error.emit("KeyAuth not initialized")
                return
            
            self.progress.emit("Authenticating...")
            
            result = manager.authenticate_user(self.auth_type, **self.auth_data)
            self.finished.emit(result)
            
        except Exception as e:
            self.error.emit(str(e))


class ModernAuthDialog(QDialog):
    """Modern authentication dialog with KeyAuth integration"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SC Kill Tracker - Authentication")
        self.setFixedSize(450, 600)
        self.setWindowFlags(Qt.Dialog | Qt.WindowCloseButtonHint)
        
        # Apply modern styling
        self.setStyleSheet("""
            QDialog {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #3c3c3c;
            }
            QTabBar::tab {
                background-color: #555555;
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #0078d4;
            }
            QLineEdit {
                background-color: #404040;
                border: 2px solid #555555;
                border-radius: 4px;
                padding: 8px;
                color: #ffffff;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #0078d4;
            }
            QPushButton {
                background-color: #0078d4;
                border: none;
                border-radius: 4px;
                padding: 10px;
                color: #ffffff;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:pressed {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #555555;
                color: #888888;
            }
            QLabel {
                color: #ffffff;
                font-size: 12px;
            }
            QProgressBar {
                border: 2px solid #555555;
                border-radius: 4px;
                text-align: center;
                background-color: #404040;
            }
            QProgressBar::chunk {
                background-color: #0078d4;
                border-radius: 2px;
            }
        """)
        
        self.auth_worker = None
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header_label = QLabel("SC Kill Tracker Authentication")
        header_label.setAlignment(Qt.AlignCenter)
        header_font = QFont()
        header_font.setPointSize(16)
        header_font.setBold(True)
        header_label.setFont(header_font)
        layout.addWidget(header_label)
        
        # Subtitle
        subtitle = QLabel("Secure authentication powered by KeyAuth")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #cccccc; font-size: 11px;")
        layout.addWidget(subtitle)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.create_login_tab()
        self.create_register_tab()
        self.create_license_tab()
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #ffaa00; font-size: 11px;")
        layout.addWidget(self.status_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        button_layout.addStretch()
        
        self.auth_button = QPushButton("Authenticate")
        self.auth_button.clicked.connect(self.authenticate)
        self.auth_button.setDefault(True)
        button_layout.addWidget(self.auth_button)
        
        layout.addLayout(button_layout)
    
    def create_login_tab(self):
        """Create login tab"""
        login_widget = QWidget()
        layout = QVBoxLayout(login_widget)
        layout.setSpacing(15)
        
        # Username
        layout.addWidget(QLabel("Username:"))
        self.login_username = QLineEdit()
        self.login_username.setPlaceholderText("Enter your username")
        layout.addWidget(self.login_username)
        
        # Password
        layout.addWidget(QLabel("Password:"))
        self.login_password = QLineEdit()
        self.login_password.setEchoMode(QLineEdit.Password)
        self.login_password.setPlaceholderText("Enter your password")
        layout.addWidget(self.login_password)
        
        # 2FA Code (optional)
        layout.addWidget(QLabel("2FA Code (optional):"))
        self.login_2fa = QLineEdit()
        self.login_2fa.setPlaceholderText("Enter 2FA code if enabled")
        layout.addWidget(self.login_2fa)
        
        # Remember me
        self.remember_login = QCheckBox("Remember credentials")
        layout.addWidget(self.remember_login)
        
        layout.addStretch()
        
        self.tab_widget.addTab(login_widget, "Login")
    
    def create_register_tab(self):
        """Create registration tab"""
        register_widget = QWidget()
        layout = QVBoxLayout(register_widget)
        layout.setSpacing(15)
        
        # Username
        layout.addWidget(QLabel("Username:"))
        self.register_username = QLineEdit()
        self.register_username.setPlaceholderText("Choose a username")
        layout.addWidget(self.register_username)
        
        # Password
        layout.addWidget(QLabel("Password:"))
        self.register_password = QLineEdit()
        self.register_password.setEchoMode(QLineEdit.Password)
        self.register_password.setPlaceholderText("Choose a password")
        layout.addWidget(self.register_password)
        
        # Confirm Password
        layout.addWidget(QLabel("Confirm Password:"))
        self.register_confirm = QLineEdit()
        self.register_confirm.setEchoMode(QLineEdit.Password)
        self.register_confirm.setPlaceholderText("Confirm your password")
        layout.addWidget(self.register_confirm)
        
        # License Key
        layout.addWidget(QLabel("License Key:"))
        self.register_license = QLineEdit()
        self.register_license.setPlaceholderText("Enter your license key")
        layout.addWidget(self.register_license)
        
        layout.addStretch()
        
        self.tab_widget.addTab(register_widget, "Register")
    
    def create_license_tab(self):
        """Create license-only tab"""
        license_widget = QWidget()
        layout = QVBoxLayout(license_widget)
        layout.setSpacing(15)
        
        # Info label
        info_label = QLabel("Use this option if you only have a license key and want to create an account automatically.")
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #cccccc; font-size: 11px;")
        layout.addWidget(info_label)
        
        # License Key
        layout.addWidget(QLabel("License Key:"))
        self.license_key = QLineEdit()
        self.license_key.setPlaceholderText("Enter your license key")
        layout.addWidget(self.license_key)
        
        # 2FA Code (optional)
        layout.addWidget(QLabel("2FA Code (optional):"))
        self.license_2fa = QLineEdit()
        self.license_2fa.setPlaceholderText("Enter 2FA code if enabled")
        layout.addWidget(self.license_2fa)
        
        layout.addStretch()
        
        self.tab_widget.addTab(license_widget, "License Only")
    
    def authenticate(self):
        """Start authentication process"""
        current_tab = self.tab_widget.currentIndex()
        
        # Validate inputs
        if current_tab == 0:  # Login
            if not self.login_username.text() or not self.login_password.text():
                QMessageBox.warning(self, "Input Error", "Please enter username and password")
                return
            
            auth_data = {
                "username": self.login_username.text(),
                "password": self.login_password.text(),
                "code": self.login_2fa.text() if self.login_2fa.text() else None
            }
            auth_type = "login"
            
        elif current_tab == 1:  # Register
            if not all([self.register_username.text(), self.register_password.text(), 
                       self.register_confirm.text(), self.register_license.text()]):
                QMessageBox.warning(self, "Input Error", "Please fill in all fields")
                return
            
            if self.register_password.text() != self.register_confirm.text():
                QMessageBox.warning(self, "Password Error", "Passwords do not match")
                return
            
            auth_data = {
                "username": self.register_username.text(),
                "password": self.register_password.text(),
                "license": self.register_license.text()
            }
            auth_type = "register"
            
        elif current_tab == 2:  # License
            if not self.license_key.text():
                QMessageBox.warning(self, "Input Error", "Please enter a license key")
                return
            
            auth_data = {
                "license": self.license_key.text(),
                "code": self.license_2fa.text() if self.license_2fa.text() else None
            }
            auth_type = "license"
        
        # Start authentication
        self.set_loading(True)
        self.auth_worker = AuthWorker(auth_type, **auth_data)
        self.auth_worker.finished.connect(self.on_auth_finished)
        self.auth_worker.error.connect(self.on_auth_error)
        self.auth_worker.progress.connect(self.on_auth_progress)
        self.auth_worker.start()
    
    def set_loading(self, loading: bool):
        """Set loading state"""
        self.auth_button.setEnabled(not loading)
        self.tab_widget.setEnabled(not loading)
        self.progress_bar.setVisible(loading)
        
        if loading:
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            self.status_label.setText("Authenticating...")
        else:
            self.progress_bar.setVisible(False)
            self.status_label.setText("")
    
    def on_auth_progress(self, message: str):
        """Handle authentication progress"""
        self.status_label.setText(message)
    
    def on_auth_finished(self, result: Dict[str, Any]):
        """Handle authentication completion"""
        self.set_loading(False)
        
        if result.get("success"):
            QMessageBox.information(self, "Success", "Authentication successful!")
            self.accept()
        else:
            error_msg = result.get("message", "Authentication failed")
            
            if result.get("banned"):
                QMessageBox.critical(self, "Access Denied", error_msg)
                self.reject()
            else:
                QMessageBox.warning(self, "Authentication Failed", error_msg)
    
    def on_auth_error(self, error: str):
        """Handle authentication error"""
        self.set_loading(False)
        QMessageBox.critical(self, "Error", f"Authentication error: {error}")


class KeyAuthSetupDialog(QDialog):
    """Dialog for initial KeyAuth setup"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("KeyAuth Setup")
        self.setFixedSize(400, 300)
        self.setModal(True)
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup UI for KeyAuth configuration"""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        
        # Header
        header = QLabel("KeyAuth Configuration")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #0078d4;")
        layout.addWidget(header)
        
        # Description
        desc = QLabel("Enter your KeyAuth application secret to enable authentication.")
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc)
        
        # Secret input
        layout.addWidget(QLabel("Application Secret:"))
        self.secret_input = QLineEdit()
        self.secret_input.setEchoMode(QLineEdit.Password)
        self.secret_input.setPlaceholderText("Enter your KeyAuth secret")
        layout.addWidget(self.secret_input)
        
        # Info
        info = QLabel("You can find this in your KeyAuth dashboard under Application Settings.")
        info.setStyleSheet("color: #666666; font-size: 10px;")
        info.setWordWrap(True)
        layout.addWidget(info)
        
        layout.addStretch()
        
        # Buttons
        button_layout = QHBoxLayout()
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        button_layout.addStretch()
        
        setup_btn = QPushButton("Setup KeyAuth")
        setup_btn.clicked.connect(self.setup_keyauth)
        setup_btn.setDefault(True)
        button_layout.addWidget(setup_btn)
        
        layout.addLayout(button_layout)
    
    def setup_keyauth(self):
        """Setup KeyAuth with provided secret"""
        secret = self.secret_input.text().strip()
        if not secret:
            QMessageBox.warning(self, "Input Error", "Please enter your KeyAuth secret")
            return
        
        if initialize_keyauth(secret):
            QMessageBox.information(self, "Success", "KeyAuth initialized successfully!")
            self.accept()
        else:
            QMessageBox.critical(self, "Error", "Failed to initialize KeyAuth. Please check your secret.")


def show_auth_dialog(parent=None) -> bool:
    """Show authentication dialog and return success status"""
    # Check if KeyAuth is initialized
    if not get_keyauth_manager():
        setup_dialog = KeyAuthSetupDialog(parent)
        if setup_dialog.exec() != QDialog.Accepted:
            return False
    
    # Show authentication dialog
    auth_dialog = ModernAuthDialog(parent)
    return auth_dialog.exec() == QDialog.Accepted


def main():
    """Test the authentication dialog"""
    app = QApplication(sys.argv)
    
    # Test the dialog
    if show_auth_dialog():
        print("Authentication successful!")
    else:
        print("Authentication cancelled or failed")
    
    sys.exit(0)


if __name__ == "__main__":
    main()
