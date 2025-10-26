#!/usr/bin/env python3
"""
Database migration to add audit_log table
Run this after updating to version 7.4.0
"""

import sys
import os

# Set up the path to find main.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, db, AuditLog

def migrate():
    """Add audit_log table to database"""
    with app.app_context():
        try:
            # Check if table already exists
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            if 'audit_log' in inspector.get_table_names():
                print("[Migration] ✓ audit_log table already exists")
                return True
            
            print("[Migration] Creating audit_log table...")
            db.create_all()
            print("[Migration] ✓ audit_log table created successfully")
            
            # Add initial audit log entry for the migration
            from datetime import datetime
            migration_log = AuditLog(
                user_id=None,
                username='system',
                action='database_migration',
                category='admin',
                details='Created audit_log table - version 7.4.0',
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
    print("caseScope v7.4.0 Database Migration")
    print("Adding audit_log table for audit logging feature")
    print("="*80)
    
    success = migrate()
    
    if success:
        print("\n[Migration] ✓ Migration completed successfully")
        print("[Migration] Audit logging is now active")
        sys.exit(0)
    else:
        print("\n[Migration] ✗ Migration failed")
        sys.exit(1)

