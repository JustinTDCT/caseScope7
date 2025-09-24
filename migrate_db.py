#!/usr/bin/env python3
"""
Database migration script for caseScope v7.0.28
Adds error_message column to CaseFile table
"""

import sqlite3
import os
import sys

def migrate_database():
    """Add error_message column to CaseFile table if it doesn't exist"""
    db_path = '/opt/casescope/data/casescope.db'
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if error_message column exists
        cursor.execute("PRAGMA table_info(case_file);")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'error_message' not in columns:
            print("Adding error_message column to case_file table...")
            cursor.execute("ALTER TABLE case_file ADD COLUMN error_message TEXT;")
            conn.commit()
            print("Migration completed successfully")
        else:
            print("error_message column already exists")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"Migration failed: {e}")
        return False

if __name__ == "__main__":
    if migrate_database():
        sys.exit(0)
    else:
        sys.exit(1)
