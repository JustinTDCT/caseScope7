#!/usr/bin/env python3
"""
caseScope v9.4.0 Database Migration
Adds statistics and linking fields for performance optimization

Changes:
- Case: Add total_files, total_events, total_events_with_iocs, total_events_with_sigma
- CaseFile: Add ioc_event_count, sigma_event_count, upload_type, opensearch_key, is_tagged
"""

import sys
import os
from sqlalchemy import create_engine, text, inspect

# Database path
db_path = "/opt/casescope/data/casescope.db"

if not os.path.exists(db_path):
    print(f"❌ Database not found: {db_path}")
    sys.exit(1)

print(f"✓ Found database: {db_path}")

# Create engine
engine = create_engine(f'sqlite:///{db_path}')
inspector = inspect(engine)

print("\n" + "="*80)
print("caseScope v9.4.0 Database Migration")
print("Adding statistics and linking fields for performance")
print("="*80 + "\n")

# Check existing columns
print("Checking current schema...")
case_columns = {col['name'] for col in inspector.get_columns('case')}
case_file_columns = {col['name'] for col in inspector.get_columns('case_file')}

print(f"✓ Case table has {len(case_columns)} columns")
print(f"✓ CaseFile table has {len(case_file_columns)} columns")

changes_made = 0

with engine.connect() as conn:
    # Start transaction
    trans = conn.begin()
    
    try:
        # ===== CASE TABLE CHANGES =====
        print("\n" + "-"*80)
        print("Updating Case table...")
        print("-"*80)
        
        case_fields = [
            ('total_files', 'INTEGER DEFAULT 0'),
            ('total_events', 'BIGINT DEFAULT 0'),
            ('total_events_with_iocs', 'INTEGER DEFAULT 0'),
            ('total_events_with_sigma', 'INTEGER DEFAULT 0')
        ]
        
        for field_name, field_type in case_fields:
            if field_name not in case_columns:
                print(f"  Adding column: {field_name} ({field_type})")
                # Use double quotes to escape 'case' reserved keyword
                conn.execute(text(f'ALTER TABLE "case" ADD COLUMN {field_name} {field_type}'))
                changes_made += 1
            else:
                print(f"  ✓ Column already exists: {field_name}")
        
        # ===== CASE_FILE TABLE CHANGES =====
        print("\n" + "-"*80)
        print("Updating CaseFile table...")
        print("-"*80)
        
        case_file_fields = [
            ('ioc_event_count', 'INTEGER DEFAULT 0'),
            ('sigma_event_count', 'INTEGER DEFAULT 0'),
            ('upload_type', "VARCHAR(50) DEFAULT 'http'"),
            ('opensearch_key', 'VARCHAR(255)'),
            ('is_tagged', 'BOOLEAN DEFAULT 0')
        ]
        
        for field_name, field_type in case_file_fields:
            if field_name not in case_file_columns:
                print(f"  Adding column: {field_name} ({field_type})")
                conn.execute(text(f"ALTER TABLE case_file ADD COLUMN {field_name} {field_type}"))
                changes_made += 1
            else:
                print(f"  ✓ Column already exists: {field_name}")
        
        # Create index on opensearch_key if it doesn't exist
        print("\n" + "-"*80)
        print("Creating indexes...")
        print("-"*80)
        
        indexes = inspector.get_indexes('case_file')
        index_names = {idx['name'] for idx in indexes}
        
        if 'ix_case_file_opensearch_key' not in index_names:
            print("  Creating index: ix_case_file_opensearch_key")
            conn.execute(text("CREATE INDEX ix_case_file_opensearch_key ON case_file(opensearch_key)"))
            changes_made += 1
        else:
            print("  ✓ Index already exists: ix_case_file_opensearch_key")
        
        # Commit transaction
        trans.commit()
        
        print("\n" + "="*80)
        print(f"✓ Migration completed successfully!")
        print(f"  Total changes made: {changes_made}")
        print("="*80 + "\n")
        
        if changes_made > 0:
            print("⚠️  IMPORTANT: Restart caseScope services for changes to take effect:")
            print("   sudo systemctl restart casescope-web")
            print("   sudo systemctl restart casescope-worker\n")
            print("📝 NOTE: Run backfill script to populate statistics for existing files:")
            print("   python3 /opt/casescope/app/backfill_statistics_v9_4_0.py\n")
        else:
            print("✓ No changes needed - database already up to date\n")
        
    except Exception as e:
        trans.rollback()
        print(f"\n❌ Migration failed: {e}")
        print("   Transaction rolled back - no changes made")
        sys.exit(1)

print("Migration script completed.")

