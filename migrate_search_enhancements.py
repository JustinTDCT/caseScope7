#!/usr/bin/env python3
"""
Database migration to add saved_search and search_history tables
Run this after updating to version 7.6.0
"""

import sys
import os

# Set up the path to find main.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, db, SavedSearch, SearchHistory

def migrate():
    """Add saved_search and search_history tables to database"""
    with app.app_context():
        try:
            # Check if tables already exist
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            existing_tables = inspector.get_table_names()
            
            if 'saved_search' in existing_tables and 'search_history' in existing_tables:
                print("[Migration] ✓ saved_search and search_history tables already exist")
                return True
            
            print("[Migration] Creating saved_search and search_history tables...")
            db.create_all()
            print("[Migration] ✓ Tables created successfully")
            
            return True
            
        except Exception as e:
            print(f"[Migration] ✗ Error: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == '__main__':
    print("="*80)
    print("caseScope v7.6.0 Database Migration")
    print("Adding saved_search and search_history tables for search enhancements")
    print("="*80)
    
    success = migrate()
    
    if success:
        print("\n[Migration] ✓ Migration completed successfully")
        print("[Migration] Search enhancements ready")
        sys.exit(0)
    else:
        print("\n[Migration] ✗ Migration failed")
        sys.exit(1)

