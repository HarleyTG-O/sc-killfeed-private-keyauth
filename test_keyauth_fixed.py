#!/usr/bin/env python3
"""
Test the fixed KeyAuth integration
"""

# Install mock win32 modules first
import mock_win32

import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_keyauth_import():
    """Test KeyAuth library import"""
    print("Testing KeyAuth library import...")
    
    try:
        from keyauth import Keyauth
        print("✓ KeyAuth library imported successfully")
        return True
    except ImportError as e:
        print(f"❌ KeyAuth import failed: {e}")
        return False

def test_keyauth_integration():
    """Test our KeyAuth integration wrapper"""
    print("\nTesting KeyAuth integration wrapper...")
    
    try:
        from keyauth_integration import KeyAuthWrapper, initialize_keyauth, get_keyauth_manager
        print("✓ KeyAuth integration imported successfully")
        
        # Test initialization
        print("Testing initialization...")
        if initialize_keyauth():
            print("✓ KeyAuth initialized successfully")
            
            manager = get_keyauth_manager()
            if manager:
                print("✓ KeyAuth manager created successfully")
                print(f"  Manager initialized: {manager.api.initialized}")
                return True
            else:
                print("❌ KeyAuth manager not created")
                return False
        else:
            print("❌ KeyAuth initialization failed")
            return False
            
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_getchecksum():
    """Test the getchecksum function"""
    print("\nTesting getchecksum function...")
    
    try:
        from keyauth_integration import getchecksum
        checksum = getchecksum()
        print(f"✓ Checksum generated: {checksum}")
        return True
    except Exception as e:
        print(f"❌ Checksum test failed: {e}")
        return False

def main():
    """Main test function"""
    print("=" * 60)
    print("KeyAuth Integration Fix Test")
    print("=" * 60)
    
    tests = [
        ("KeyAuth Library Import", test_keyauth_import),
        ("Checksum Function", test_getchecksum),
        ("KeyAuth Integration", test_keyauth_integration),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        result = test_func()
        results.append((test_name, result))
    
    print("\n" + "=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    
    all_passed = True
    for test_name, result in results:
        status = "✓ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
        if not result:
            all_passed = False
    
    if all_passed:
        print("\n🎉 All tests passed! KeyAuth integration is working.")
    else:
        print("\n⚠️  Some tests failed. Check the errors above.")
    
    return all_passed

if __name__ == "__main__":
    try:
        success = main()
        input(f"\nPress Enter to exit...")
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")
        sys.exit(1)
