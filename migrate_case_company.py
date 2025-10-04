#!/usr/bin/env python3
"""
Migration script to add company and DFIR-IRIS integration fields to case table
Adds: company, iris_company_id, iris_case_id, iris_synced_at
"""

import sys
import sqlite3
from pathlib import Path

def migrate_case_company():
    """Add company and DFIR-IRIS fields to case table"""
    
    db_path = Path('/opt/casescope/data/casescope.db')
    
    if not db_path.exists():
        print(f"❌ Database not found at {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(case)")
        columns = [col[1] for col in cursor.fetchall()]
        
        fields_to_add = []
        
        if 'company' not in columns:
            fields_to_add.append(('company', 'VARCHAR(200)', 'Company/Customer name'))
        
        if 'iris_company_id' not in columns:
            fields_to_add.append(('iris_company_id', 'INTEGER', 'DFIR-IRIS company ID'))
        
        if 'iris_case_id' not in columns:
            fields_to_add.append(('iris_case_id', 'INTEGER', 'DFIR-IRIS case ID'))
        
        if 'iris_synced_at' not in columns:
            fields_to_add.append(('iris_synced_at', 'TIMESTAMP', 'Last DFIR-IRIS sync timestamp'))
        
        if not fields_to_add:
            print("✓ All columns already exist in case table")
            conn.close()
            return True
        
        print(f"Adding {len(fields_to_add)} column(s) to case table...")
        
        # Add each column
        for col_name, col_type, description in fields_to_add:
            print(f"  Adding column '{col_name}' ({description})...")
            cursor.execute(f"""
                ALTER TABLE case 
                ADD COLUMN {col_name} {col_type}
            """)
            print(f"  ✓ Column '{col_name}' added")
        
        conn.commit()
        
        print("✓ Migration completed successfully")
        print("\n📋 What was added:")
        print("   • company - Company/Customer name for organization")
        print("   • iris_company_id - DFIR-IRIS company ID (for sync tracking)")
        print("   • iris_case_id - DFIR-IRIS case ID (for sync tracking)")
        print("   • iris_synced_at - Last sync timestamp")
        print("\n📋 Next steps:")
        print("   1. Create new cases with company name")
        print("   2. Edit existing cases to add company if needed")
        print("   3. Configure DFIR-IRIS in System Settings")
        print("   4. DFIR-IRIS sync will use company field automatically")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print("=" * 80)
    print("CASE COMPANY & DFIR-IRIS INTEGRATION MIGRATION")
    print("=" * 80)
    print("\nThis script adds company and DFIR-IRIS tracking fields to cases.")
    print()
    
    success = migrate_case_company()
    sys.exit(0 if success else 1)

