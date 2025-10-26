#!/usr/bin/env python3
"""
Database migration: Add is_hidden field to case_file table

This migration adds the is_hidden boolean field to support hiding files from:
- File lists
- File management pages
- Search queries

Files with 0 events are automatically hidden.
Users can manually hide/unhide files via UI.
"""

import sqlite3
import sys
from pathlib import Path

def migrate_add_is_hidden():
    """Add is_hidden column to case_file table"""
    
    db_path = '/opt/casescope/data/casescope.db'
    
    # Check if database exists
    if not Path(db_path).exists():
        print(f"❌ Database not found: {db_path}")
        print("   This script should be run on the server after installation.")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if column already exists
        cursor.execute("PRAGMA table_info(case_file)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'is_hidden' in columns:
            print("✓ Column 'is_hidden' already exists in case_file table")
            conn.close()
            return True
        
        print("Adding 'is_hidden' column to case_file table...")
        
        # Add the column
        cursor.execute("""
            ALTER TABLE case_file 
            ADD COLUMN is_hidden BOOLEAN DEFAULT 0
        """)
        
        # Auto-hide files with 0 events
        cursor.execute("""
            UPDATE case_file 
            SET is_hidden = 1 
            WHERE event_count = 0 AND is_deleted = 0
        """)
        
        hidden_count = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        print(f"✓ Successfully added 'is_hidden' column")
        print(f"✓ Auto-hidden {hidden_count} files with 0 events")
        print("\nMigration complete! Hidden files:")
        print("  - Won't appear in file lists (unless 'Show Hidden' checked)")
        print("  - Won't appear in search results")
        print("  - WILL still be indexed/re-indexed/SIGMA/IOC processed")
        
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == '__main__':
    print("="*80)
    print("Database Migration: Add is_hidden field to case_file")
    print("="*80)
    
    success = migrate_add_is_hidden()
    
    if success:
        print("\n✓ Migration successful!")
        sys.exit(0)
    else:
        print("\n❌ Migration failed!")
        sys.exit(1)

