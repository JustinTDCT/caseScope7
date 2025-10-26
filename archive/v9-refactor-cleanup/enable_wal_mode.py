#!/usr/bin/env python3
"""
Enable SQLite WAL mode permanently on the caseScope database
Run this once to set WAL mode on the database file itself
"""

import sqlite3
import sys

DB_PATH = '/opt/casescope/data/casescope.db'

def enable_wal_mode():
    """Enable WAL mode on the SQLite database"""
    try:
        # Connect to the database
        conn = sqlite3.connect(DB_PATH, timeout=30)
        cursor = conn.cursor()
        
        # Check current journal mode
        cursor.execute("PRAGMA journal_mode;")
        current_mode = cursor.fetchone()[0]
        print(f"Current journal mode: {current_mode}")
        
        if current_mode.lower() != 'wal':
            # Enable WAL mode
            cursor.execute("PRAGMA journal_mode=WAL;")
            new_mode = cursor.fetchone()[0]
            print(f"New journal mode: {new_mode}")
            
            # Set busy timeout
            cursor.execute("PRAGMA busy_timeout=30000;")
            print("Set busy_timeout to 30000ms")
            
            # Verify WAL mode
            cursor.execute("PRAGMA journal_mode;")
            verify_mode = cursor.fetchone()[0]
            if verify_mode.lower() == 'wal':
                print("✓ WAL mode enabled successfully!")
                print("✓ Database will now support concurrent reads during writes")
            else:
                print(f"⚠ Warning: Expected WAL mode, got {verify_mode}")
                sys.exit(1)
        else:
            print("✓ WAL mode already enabled")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"✗ Error enabling WAL mode: {e}")
        sys.exit(1)

if __name__ == '__main__':
    print("="*60)
    print("caseScope - Enable SQLite WAL Mode")
    print("="*60)
    enable_wal_mode()
    print("="*60)

