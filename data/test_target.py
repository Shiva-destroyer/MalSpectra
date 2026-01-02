#!/usr/bin/env python3
"""
Test Target for API Hooking
A simple program that performs file operations

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import time

def main():
    """Simple test program for API hooking."""
    
    print("=== API Hooking Test Target ===")
    print("This program performs basic file operations\n")
    
    # Test file operations
    print("[1] Creating test file...")
    with open("test_output.txt", "w") as f:
        f.write("Hello from test target!\n")
        f.write("Testing API hooks...\n")
    print("✓ File created: test_output.txt")
    
    time.sleep(1)
    
    # Test file reading
    print("\n[2] Reading test file...")
    with open("test_output.txt", "r") as f:
        content = f.read()
        print(f"✓ Read {len(content)} bytes")
    
    time.sleep(1)
    
    # Test file append
    print("\n[3] Appending to file...")
    with open("test_output.txt", "a") as f:
        f.write("Additional line\n")
    print("✓ File updated")
    
    time.sleep(1)
    
    # Cleanup
    print("\n[4] Cleaning up...")
    import os
    os.remove("test_output.txt")
    print("✓ File removed")
    
    print("\n=== Test Complete ===")
    print("Run with LD_PRELOAD to see hooked calls:")
    print("  LD_PRELOAD=./fopen_hook.so python3 test_target.py")

if __name__ == "__main__":
    main()
