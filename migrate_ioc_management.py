#!/usr/bin/env python3
"""
Database migration to add IOC management tables
Run this after updating to version 7.14.0
"""

import sys
import os

# Set up the path to find main.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, db, IOC, IOCMatch

def migrate():
    """Add ioc and ioc_match tables to database"""
    with app.app_context():
        try:
            # Check if tables already exist
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            
            tables_to_create = []
            if 'ioc' not in inspector.get_table_names():
                tables_to_create.append('ioc')
            if 'ioc_match' not in inspector.get_table_names():
                tables_to_create.append('ioc_match')
            
            if not tables_to_create:
                print("[Migration] ✓ IOC tables already exist")
                return True
            
            print(f"[Migration] Creating tables: {', '.join(tables_to_create)}")
            db.create_all()
            print("[Migration] ✓ IOC tables created successfully")
            
            # Add initial audit log entry for the migration
            from datetime import datetime
            from main import AuditLog
            migration_log = AuditLog(
                user_id=None,
                username='system',
                action='database_migration',
                category='admin',
                details='Created IOC management tables (ioc, ioc_match) for threat hunting - version 7.14.0',
                ip_address='127.0.0.1',
                timestamp=datetime.utcnow(),
                success=True
            )
            db.session.add(migration_log)
            db.session.commit()
            print("[Migration] ✓ Added migration audit log entry")
            
            return True
            
        except Exception as e:
            print(f"[Migration] ✗ Error: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == '__main__':
    print("="*80)
    print("caseScope v7.14.0 Database Migration")
    print("Adding IOC (Indicator of Compromise) management tables for threat hunting")
    print("="*80)
    
    success = migrate()
    
    if success:
        print("\n[Migration] ✓ Migration completed successfully")
        print("[Migration] IOC management is now active")
        print("[Migration] Analysts can now add IOCs and hunt for threats")
        sys.exit(0)
    else:
        print("\n[Migration] ✗ Migration failed")
        sys.exit(1)

