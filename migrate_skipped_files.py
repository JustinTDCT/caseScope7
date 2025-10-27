#!/usr/bin/env python3
"""
caseScope v9.4.13 - Add SkippedFile Audit Table
Copyright (c) 2025 Justin Dube <casescope@thedubes.net>

Migration to add skipped_file table for complete upload audit trail.
"""

import sqlite3
import sys
from pathlib import Path

# Database path
db_path = '/opt/casescope/data/casescope.db'

def migrate():
    """Add skipped_file table to database"""
    
    # Check if database exists
    if not Path(db_path).exists():
        print(f"ERROR: Database not found: {db_path}")
        sys.exit(1)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if table already exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='skipped_file'
        """)
        
        if cursor.fetchone():
            print("✓ skipped_file table already exists")
            return
        
        # Create skipped_file table
        print("Creating skipped_file table...")
        cursor.execute("""
            CREATE TABLE skipped_file (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                filename VARCHAR(500) NOT NULL,
                file_size BIGINT NOT NULL,
                file_hash VARCHAR(64),
                skip_reason VARCHAR(50) NOT NULL,
                skip_details TEXT,
                upload_type VARCHAR(20) DEFAULT 'local',
                skipped_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES "case" (id)
            )
        """)
        
        # Create index for faster queries
        cursor.execute("""
            CREATE INDEX idx_skipped_file_case_id 
            ON skipped_file (case_id)
        """)
        
        cursor.execute("""
            CREATE INDEX idx_skipped_file_skip_reason 
            ON skipped_file (skip_reason)
        """)
        
        cursor.execute("""
            CREATE INDEX idx_skipped_file_skipped_at 
            ON skipped_file (skipped_at)
        """)
        
        conn.commit()
        print("✓ skipped_file table created successfully")
        print("✓ Indexes created successfully")
        
    except Exception as e:
        print(f"ERROR: Migration failed: {e}")
        conn.rollback()
        sys.exit(1)
    finally:
        conn.close()

if __name__ == '__main__':
    print("=" * 80)
    print("caseScope v9.4.13 - Add SkippedFile Audit Table")
    print("=" * 80)
    migrate()
    print("✓ Migration complete!")

