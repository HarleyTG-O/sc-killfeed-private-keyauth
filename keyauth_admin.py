"""
KeyAuth Admin Panel for SC Kill Tracker
Advanced user management, HWID banning, and monitoring capabilities
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import requests
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

class KeyAuthAdminAPI:
    """KeyAuth Seller API for admin functions"""
    
    def __init__(self, seller_key: str, api_url: str = "https://keyauth.win/api/seller/"):
        self.seller_key = seller_key
        self.api_url = api_url
        self.logger = logging.getLogger("KeyAuthAdmin")
    
    def _make_request(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make request to seller API"""
        try:
            params["sellerkey"] = self.seller_key
            response = requests.get(self.api_url, params=params, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Admin API request failed: {e}")
            return None
    
    def get_all_users(self, app_name: str) -> List[Dict[str, Any]]:
        """Get all users for application"""
        params = {
            "type": "fetchallusers",
            "name": app_name
        }
        
        response = self._make_request(params)
        if response and response.get("success"):
            return response.get("users", [])
        return []
    
    def ban_user(self, username: str, reason: str, app_name: str) -> bool:
        """Ban user by username"""
        params = {
            "type": "ban",
            "user": username,
            "reason": reason,
            "name": app_name
        }
        
        response = self._make_request(params)
        return response and response.get("success", False)
    
    def unban_user(self, username: str, app_name: str) -> bool:
        """Unban user by username"""
        params = {
            "type": "unban",
            "user": username,
            "name": app_name
        }
        
        response = self._make_request(params)
        return response and response.get("success", False)
    
    def blacklist_hwid(self, hwid: str, app_name: str) -> bool:
        """Blacklist HWID"""
        params = {
            "type": "black",
            "hwid": hwid,
            "name": app_name
        }
        
        response = self._make_request(params)
        return response and response.get("success", False)
    
    def unblacklist_hwid(self, hwid: str, app_name: str) -> bool:
        """Remove HWID from blacklist"""
        params = {
            "type": "unblack",
            "hwid": hwid,
            "name": app_name
        }
        
        response = self._make_request(params)
        return response and response.get("success", False)
    
    def get_blacklisted_hwids(self, app_name: str) -> List[str]:
        """Get all blacklisted HWIDs"""
        params = {
            "type": "fetchallblacklist",
            "name": app_name
        }
        
        response = self._make_request(params)
        if response and response.get("success"):
            return [item["hwid"] for item in response.get("blacklist", [])]
        return []
    
    def create_license(self, mask: str, amount: int, duration: int, app_name: str) -> List[str]:
        """Create license keys"""
        params = {
            "type": "add",
            "format": mask,
            "amount": str(amount),
            "duration": str(duration),
            "name": app_name
        }
        
        response = self._make_request(params)
        if response and response.get("success"):
            return response.get("keys", [])
        return []
    
    def delete_license(self, license_key: str, app_name: str) -> bool:
        """Delete license key"""
        params = {
            "type": "del",
            "key": license_key,
            "name": app_name
        }
        
        response = self._make_request(params)
        return response and response.get("success", False)
    
    def get_app_logs(self, app_name: str) -> List[Dict[str, Any]]:
        """Get application logs"""
        params = {
            "type": "fetchalllogs",
            "name": app_name
        }
        
        response = self._make_request(params)
        if response and response.get("success"):
            return response.get("logs", [])
        return []


class KeyAuthAdminPanel:
    """GUI Admin Panel for KeyAuth management"""
    
    def __init__(self, seller_key: str, app_name: str = "SCKillTrac"):
        self.api = KeyAuthAdminAPI(seller_key)
        self.app_name = app_name
        self.root = None
        self.users_tree = None
        self.hwid_tree = None
        self.logs_text = None
        
        self.users_data = []
        self.blacklisted_hwids = []
        
    def create_gui(self):
        """Create the admin panel GUI"""
        self.root = tk.Tk()
        self.root.title(f"KeyAuth Admin Panel - {self.app_name}")
        self.root.geometry("1200x800")
        
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Users tab
        users_frame = ttk.Frame(notebook)
        notebook.add(users_frame, text="Users")
        self._create_users_tab(users_frame)
        
        # HWID Blacklist tab
        hwid_frame = ttk.Frame(notebook)
        notebook.add(hwid_frame, text="HWID Blacklist")
        self._create_hwid_tab(hwid_frame)
        
        # Licenses tab
        license_frame = ttk.Frame(notebook)
        notebook.add(license_frame, text="Licenses")
        self._create_license_tab(license_frame)
        
        # Logs tab
        logs_frame = ttk.Frame(notebook)
        notebook.add(logs_frame, text="Logs")
        self._create_logs_tab(logs_frame)
        
        # Auto-refresh data
        self._start_auto_refresh()
        
        return self.root
    
    def _create_users_tab(self, parent):
        """Create users management tab"""
        # Control frame
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Refresh Users", command=self._refresh_users).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Ban Selected", command=self._ban_selected_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Unban Selected", command=self._unban_selected_user).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Blacklist HWID", command=self._blacklist_user_hwid).pack(side=tk.LEFT, padx=5)
        
        # Users treeview
        columns = ("Username", "HWID", "IP", "Last Login", "Expires", "Subscription")
        self.users_tree = ttk.Treeview(parent, columns=columns, show="headings", height=20)
        
        for col in columns:
            self.users_tree.heading(col, text=col)
            self.users_tree.column(col, width=150)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.users_tree.yview)
        h_scrollbar = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.users_tree.xview)
        self.users_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.users_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _create_hwid_tab(self, parent):
        """Create HWID blacklist management tab"""
        # Control frame
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Refresh HWIDs", command=self._refresh_hwids).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Add HWID", command=self._add_hwid_dialog).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Remove Selected", command=self._remove_selected_hwid).pack(side=tk.LEFT, padx=5)
        
        # HWID treeview
        columns = ("HWID", "Date Added")
        self.hwid_tree = ttk.Treeview(parent, columns=columns, show="headings", height=25)
        
        for col in columns:
            self.hwid_tree.heading(col, text=col)
            self.hwid_tree.column(col, width=300)
        
        # Scrollbar
        hwid_scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.hwid_tree.yview)
        self.hwid_tree.configure(yscrollcommand=hwid_scrollbar.set)
        
        self.hwid_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hwid_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def _create_license_tab(self, parent):
        """Create license management tab"""
        # License creation frame
        create_frame = ttk.LabelFrame(parent, text="Create Licenses")
        create_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # License format
        ttk.Label(create_frame, text="Format:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.license_format = ttk.Entry(create_frame, width=30)
        self.license_format.insert(0, "SCKT-****-****-****")
        self.license_format.grid(row=0, column=1, padx=5, pady=5)
        
        # Amount
        ttk.Label(create_frame, text="Amount:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.license_amount = ttk.Spinbox(create_frame, from_=1, to=100, width=10)
        self.license_amount.set("1")
        self.license_amount.grid(row=0, column=3, padx=5, pady=5)
        
        # Duration (days)
        ttk.Label(create_frame, text="Duration (days):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.license_duration = ttk.Spinbox(create_frame, from_=1, to=365, width=10)
        self.license_duration.set("30")
        self.license_duration.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Button(create_frame, text="Create Licenses", command=self._create_licenses).grid(row=1, column=2, padx=5, pady=5)
        
        # Generated licenses display
        self.license_text = scrolledtext.ScrolledText(parent, height=15)
        self.license_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _create_logs_tab(self, parent):
        """Create logs viewing tab"""
        # Control frame
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Refresh Logs", command=self._refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear Display", command=self._clear_logs).pack(side=tk.LEFT, padx=5)
        
        # Logs text area
        self.logs_text = scrolledtext.ScrolledText(parent, height=30)
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _refresh_users(self):
        """Refresh users list"""
        def refresh():
            self.users_data = self.api.get_all_users(self.app_name)
            self.root.after(0, self._update_users_display)
        
        threading.Thread(target=refresh, daemon=True).start()
    
    def _update_users_display(self):
        """Update users treeview"""
        # Clear existing items
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)
        
        # Add users
        for user in self.users_data:
            last_login = datetime.fromtimestamp(int(user.get("lastlogin", 0))).strftime("%Y-%m-%d %H:%M")
            expires = datetime.fromtimestamp(int(user.get("expires", 0))).strftime("%Y-%m-%d %H:%M")
            
            self.users_tree.insert("", tk.END, values=(
                user.get("username", ""),
                user.get("hwid", ""),
                user.get("ip", ""),
                last_login,
                expires,
                user.get("subscription", "")
            ))
    
    def _ban_selected_user(self):
        """Ban selected user"""
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a user to ban")
            return
        
        item = self.users_tree.item(selection[0])
        username = item["values"][0]
        
        reason = tk.simpledialog.askstring("Ban Reason", f"Enter reason for banning {username}:")
        if reason:
            def ban():
                success = self.api.ban_user(username, reason, self.app_name)
                if success:
                    self.root.after(0, lambda: messagebox.showinfo("Success", f"User {username} banned"))
                    self.root.after(0, self._refresh_users)
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to ban {username}"))
            
            threading.Thread(target=ban, daemon=True).start()
    
    def _unban_selected_user(self):
        """Unban selected user"""
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a user to unban")
            return
        
        item = self.users_tree.item(selection[0])
        username = item["values"][0]
        
        def unban():
            success = self.api.unban_user(username, self.app_name)
            if success:
                self.root.after(0, lambda: messagebox.showinfo("Success", f"User {username} unbanned"))
                self.root.after(0, self._refresh_users)
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to unban {username}"))
        
        threading.Thread(target=unban, daemon=True).start()
    
    def _blacklist_user_hwid(self):
        """Blacklist HWID of selected user"""
        selection = self.users_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a user")
            return
        
        item = self.users_tree.item(selection[0])
        hwid = item["values"][1]
        username = item["values"][0]
        
        if messagebox.askyesno("Confirm", f"Blacklist HWID for user {username}?"):
            def blacklist():
                success = self.api.blacklist_hwid(hwid, self.app_name)
                if success:
                    self.root.after(0, lambda: messagebox.showinfo("Success", f"HWID blacklisted for {username}"))
                    self.root.after(0, self._refresh_hwids)
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", "Failed to blacklist HWID"))
            
            threading.Thread(target=blacklist, daemon=True).start()
    
    def _refresh_hwids(self):
        """Refresh HWID blacklist"""
        def refresh():
            self.blacklisted_hwids = self.api.get_blacklisted_hwids(self.app_name)
            self.root.after(0, self._update_hwids_display)
        
        threading.Thread(target=refresh, daemon=True).start()
    
    def _update_hwids_display(self):
        """Update HWID treeview"""
        # Clear existing items
        for item in self.hwid_tree.get_children():
            self.hwid_tree.delete(item)
        
        # Add HWIDs
        for hwid in self.blacklisted_hwids:
            self.hwid_tree.insert("", tk.END, values=(hwid, datetime.now().strftime("%Y-%m-%d")))
    
    def _add_hwid_dialog(self):
        """Show dialog to add HWID to blacklist"""
        hwid = tk.simpledialog.askstring("Add HWID", "Enter HWID to blacklist:")
        if hwid:
            def add():
                success = self.api.blacklist_hwid(hwid, self.app_name)
                if success:
                    self.root.after(0, lambda: messagebox.showinfo("Success", "HWID blacklisted"))
                    self.root.after(0, self._refresh_hwids)
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", "Failed to blacklist HWID"))
            
            threading.Thread(target=add, daemon=True).start()
    
    def _remove_selected_hwid(self):
        """Remove selected HWID from blacklist"""
        selection = self.hwid_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an HWID to remove")
            return
        
        item = self.hwid_tree.item(selection[0])
        hwid = item["values"][0]
        
        if messagebox.askyesno("Confirm", f"Remove HWID from blacklist?\n{hwid}"):
            def remove():
                success = self.api.unblacklist_hwid(hwid, self.app_name)
                if success:
                    self.root.after(0, lambda: messagebox.showinfo("Success", "HWID removed from blacklist"))
                    self.root.after(0, self._refresh_hwids)
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", "Failed to remove HWID"))
            
            threading.Thread(target=remove, daemon=True).start()
    
    def _create_licenses(self):
        """Create new license keys"""
        format_str = self.license_format.get()
        amount = int(self.license_amount.get())
        duration = int(self.license_duration.get())
        
        def create():
            keys = self.api.create_license(format_str, amount, duration, self.app_name)
            if keys:
                key_text = "\n".join(keys)
                self.root.after(0, lambda: self.license_text.insert(tk.END, f"\n--- Generated {len(keys)} licenses ---\n{key_text}\n"))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", "Failed to create licenses"))
        
        threading.Thread(target=create, daemon=True).start()
    
    def _refresh_logs(self):
        """Refresh application logs"""
        def refresh():
            logs = self.api.get_app_logs(self.app_name)
            log_text = ""
            for log in logs:
                timestamp = datetime.fromtimestamp(int(log.get("date", 0))).strftime("%Y-%m-%d %H:%M:%S")
                log_text += f"[{timestamp}] {log.get('pcuser', 'Unknown')}: {log.get('message', '')}\n"
            
            self.root.after(0, lambda: self._update_logs_display(log_text))
        
        threading.Thread(target=refresh, daemon=True).start()
    
    def _update_logs_display(self, log_text):
        """Update logs display"""
        self.logs_text.delete(1.0, tk.END)
        self.logs_text.insert(tk.END, log_text)
        self.logs_text.see(tk.END)
    
    def _clear_logs(self):
        """Clear logs display"""
        self.logs_text.delete(1.0, tk.END)
    
    def _start_auto_refresh(self):
        """Start auto-refresh of data"""
        def auto_refresh():
            while True:
                time.sleep(30)  # Refresh every 30 seconds
                self.root.after(0, self._refresh_users)
                self.root.after(0, self._refresh_hwids)
        
        threading.Thread(target=auto_refresh, daemon=True).start()
    
    def run(self):
        """Run the admin panel"""
        self.create_gui()
        self._refresh_users()
        self._refresh_hwids()
        self.root.mainloop()


def main():
    """Main function to run admin panel"""
    import tkinter.simpledialog as simpledialog
    
    root = tk.Tk()
    root.withdraw()  # Hide root window
    
    seller_key = simpledialog.askstring("KeyAuth Admin", "Enter your seller key:", show='*')
    if not seller_key:
        return
    
    root.destroy()
    
    admin_panel = KeyAuthAdminPanel(seller_key)
    admin_panel.run()


if __name__ == "__main__":
    main()
