#!/usr/bin/env python3
"""
Mock win32security module for testing KeyAuth on non-Windows systems
"""

import sys
from types import ModuleType

# Create mock win32security module
win32security = ModuleType('win32security')

def mock_lookup_account_name(system, username):
    """Mock LookupAccountName function"""
    # Return a fake SID object
    class MockSID:
        pass
    return [MockSID(), None, None]

def mock_convert_sid_to_string_sid(sid):
    """Mock ConvertSidToStringSid function"""
    return "S-1-5-21-1234567890-1234567890-1234567890-1001"

# Add mock functions to the module
win32security.LookupAccountName = mock_lookup_account_name
win32security.ConvertSidToStringSid = mock_convert_sid_to_string_sid

# Install the mock module
sys.modules['win32security'] = win32security

print("Mock win32security module installed for testing")
