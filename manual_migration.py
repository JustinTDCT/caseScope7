#!/usr/bin/env python3
"""
Manual database migration for caseScope v7.0.34
Run this directly on the server if migrate_db.py is missing
"""

import sqlite3
import os

def manual_migration():
    """Perform manual database migration"""
    db_path = '/opt/casescope/data/casescope.db'
    
    print(f"Checking database at {db_path}")
    
    if not os.path.exists(db_path):
        print("Database not found - this is normal for new installations")
        return True
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if error_message column exists in case_file table
        cursor.execute("PRAGMA table_info(case_file);")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'error_message' not in columns:
            print("Adding error_message column to case_file table...")
            cursor.execute("ALTER TABLE case_file ADD COLUMN error_message TEXT;")
            conn.commit()
            print("✅ Migration completed successfully")
        else:
            print("✅ error_message column already exists")
        
        # Verify the change
        cursor.execute("PRAGMA table_info(case_file);")
        columns = [column[1] for column in cursor.fetchall()]
        print(f"Current case_file columns: {', '.join(columns)}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False

if __name__ == "__main__":
    print("=== caseScope Manual Database Migration ===")
    success = manual_migration()
    print("=== Migration Complete ===")
    exit(0 if success else 1)
