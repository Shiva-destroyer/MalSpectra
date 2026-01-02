#!/usr/bin/env python3
"""
Harmless test script for MalSpectra sandbox testing.
This script performs safe operations for testing purposes.
"""

import os
import time

def main():
    """Safe test operations."""
    print("Test script started")
    
    # File operation (harmless)
    test_file = "/tmp/malspectra_test.txt"
    with open(test_file, 'w') as f:
        f.write("MalSpectra test data\n")
    
    # Read back
    with open(test_file, 'r') as f:
        content = f.read()
        print(f"Read: {content.strip()}")
    
    # Sleep briefly
    time.sleep(0.5)
    
    # Cleanup
    if os.path.exists(test_file):
        os.remove(test_file)
        print("Cleaned up test file")
    
    print("Test script completed successfully")

if __name__ == "__main__":
    main()
