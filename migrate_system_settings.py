#!/usr/bin/env python3
"""
Migration script to create system_settings table
Stores system-wide configuration including DFIR-IRIS integration settings
"""

import sys
import sqlite3
from pathlib import Path

def migrate_system_settings():
    """Create system_settings table"""
    
    db_path = Path('/opt/casescope/data/casescope.db')
    
    if not db_path.exists():
        print(f"❌ Database not found at {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if table already exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_settings'")
        if cursor.fetchone():
            print("✓ Table 'system_settings' already exists")
            conn.close()
            return True
        
        print("Creating 'system_settings' table...")
        
        # Create the table
        cursor.execute("""
            CREATE TABLE system_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key VARCHAR(100) NOT NULL UNIQUE,
                setting_value TEXT,
                setting_type VARCHAR(20) DEFAULT 'string',
                description TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by INTEGER,
                FOREIGN KEY (updated_by) REFERENCES user(id)
            )
        """)
        
        # Create index on setting_key for fast lookups
        cursor.execute("""
            CREATE INDEX idx_setting_key ON system_settings(setting_key)
        """)
        
        conn.commit()
        print("✓ Table created successfully")
        print("✓ Index created on setting_key")
        
        # Add default settings
        print("Adding default DFIR-IRIS settings...")
        
        defaults = [
            ('iris_enabled', 'false', 'boolean', 'Enable DFIR-IRIS integration'),
            ('iris_url', '', 'string', 'DFIR-IRIS server URL'),
            ('iris_api_key', '', 'string', 'DFIR-IRIS API key'),
            ('iris_customer_id', '1', 'integer', 'DFIR-IRIS customer ID'),
            ('iris_auto_sync', 'false', 'boolean', 'Auto-sync to DFIR-IRIS'),
        ]
        
        for key, value, stype, desc in defaults:
            cursor.execute("""
                INSERT INTO system_settings (setting_key, setting_value, setting_type, description)
                VALUES (?, ?, ?, ?)
            """, (key, value, stype, desc))
        
        conn.commit()
        print(f"✓ Added {len(defaults)} default settings")
        
        print("✓ Migration completed successfully")
        print("\n📋 Next steps:")
        print("   1. Go to System Settings page (Management → System Settings)")
        print("   2. Configure DFIR-IRIS integration if needed")
        print("   3. Test connection to verify settings")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print("=" * 80)
    print("SYSTEM SETTINGS MIGRATION")
    print("=" * 80)
    print("\nThis script will create the system_settings table for configuration management.")
    print()
    
    success = migrate_system_settings()
    sys.exit(0 if success else 1)

