#!/usr/bin/env python3
"""
Migration script to add source_filename column to ioc_match table
Adds the column and backfills data from existing matches
"""

import sys
import sqlite3
from pathlib import Path

def migrate_ioc_matches():
    """Add source_filename column to ioc_match table"""
    
    db_path = Path('/opt/casescope/casescope.db')
    
    if not db_path.exists():
        print(f"❌ Database not found at {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if column already exists
        cursor.execute("PRAGMA table_info(ioc_match)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'source_filename' in columns:
            print("✓ Column 'source_filename' already exists in ioc_match table")
            conn.close()
            return True
        
        print("Adding 'source_filename' column to ioc_match table...")
        
        # Add the column
        cursor.execute("""
            ALTER TABLE ioc_match 
            ADD COLUMN source_filename VARCHAR(300)
        """)
        
        conn.commit()
        print("✓ Column added successfully")
        
        # Backfill existing records with 'Unknown' (will be updated on next hunt)
        cursor.execute("""
            UPDATE ioc_match 
            SET source_filename = 'Unknown' 
            WHERE source_filename IS NULL
        """)
        
        updated_count = cursor.rowcount
        conn.commit()
        
        print(f"✓ Updated {updated_count} existing IOC match records")
        print("✓ Migration completed successfully")
        print("\nNote: Existing matches show 'Unknown' filename. Run IOC hunt again to populate actual filenames.")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False

if __name__ == '__main__':
    success = migrate_ioc_matches()
    sys.exit(0 if success else 1)

