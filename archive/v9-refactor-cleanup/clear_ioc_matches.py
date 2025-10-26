#!/usr/bin/env python3
"""
Utility script to clear old IOC matches
Use this to delete existing matches before re-running IOC hunt with updated code
"""

import sys
import sqlite3
from pathlib import Path

def clear_ioc_matches():
    """Delete all IOC matches from database"""
    
    db_path = Path('/opt/casescope/data/casescope.db')
    
    if not db_path.exists():
        print(f"❌ Database not found at {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get count before deletion
        cursor.execute("SELECT COUNT(*) FROM ioc_match")
        count_before = cursor.fetchone()[0]
        
        if count_before == 0:
            print("ℹ️  No IOC matches to clear")
            conn.close()
            return True
        
        print(f"Found {count_before} IOC match records")
        
        # Confirm deletion
        response = input(f"\n⚠️  Delete all {count_before} IOC matches? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("❌ Deletion cancelled")
            conn.close()
            return False
        
        # Delete all matches
        cursor.execute("DELETE FROM ioc_match")
        deleted_count = cursor.rowcount
        conn.commit()
        
        # Reset IOC statistics
        cursor.execute("UPDATE ioc SET match_count = 0, last_seen = NULL")
        conn.commit()
        
        print(f"✓ Deleted {deleted_count} IOC match records")
        print("✓ Reset IOC statistics")
        print("\n📋 Next steps:")
        print("   1. Go to IOC Management page")
        print("   2. Click 'Hunt for IOCs' button")
        print("   3. New matches will be created with updated field data")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Failed to clear IOC matches: {e}")
        return False

if __name__ == '__main__':
    print("=" * 80)
    print("IOC MATCHES CLEANUP UTILITY")
    print("=" * 80)
    print("\nThis script will delete all existing IOC match records.")
    print("Use this before re-running IOC hunt to populate new fields.")
    print()
    
    success = clear_ioc_matches()
    sys.exit(0 if success else 1)

