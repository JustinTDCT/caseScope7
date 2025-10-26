#!/usr/bin/env python3
"""
caseScope v9.4.0 Statistics Backfill Script
Populates statistics fields for existing files

Run this AFTER migrate_statistics_v9_4_0.py completes
"""

import sys
import os

# Add app directory to path
sys.path.insert(0, '/opt/casescope/app')

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from models import db, Case, CaseFile, SigmaViolation, IOCMatch, IOC
from utils import make_index_name
from aggregates import update_case_aggregates
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database path
db_path = "/opt/casescope/data/casescope.db"

if not os.path.exists(db_path):
    print(f"❌ Database not found: {db_path}")
    sys.exit(1)

print("\n" + "="*80)
print("caseScope v9.4.0 Statistics Backfill")
print("Populating statistics for existing files")
print("="*80 + "\n")

# Create engine and session
engine = create_engine(f'sqlite:///{db_path}')
Session = sessionmaker(bind=engine)
session = Session()

try:
    # Get all cases
    cases = session.query(Case).filter_by(is_active=True).all()
    total_cases = len(cases)
    
    print(f"Found {total_cases} active cases")
    print("-"*80)
    
    for case_idx, case in enumerate(cases, 1):
        print(f"\n[{case_idx}/{total_cases}] Processing Case: {case.name} (ID: {case.id})")
        
        # Get all non-deleted files for this case
        files = session.query(CaseFile).filter_by(
            case_id=case.id,
            is_deleted=False
        ).all()
        
        print(f"  Found {len(files)} files")
        
        for file_idx, case_file in enumerate(files, 1):
            print(f"    [{file_idx}/{len(files)}] {case_file.original_filename}")
            
            changes_made = []
            
            # 1. Generate opensearch_key if missing
            if not case_file.opensearch_key:
                index_name = make_index_name(case.id, case_file.original_filename)
                case_file.opensearch_key = f"case{case.id}_{index_name}"
                changes_made.append('opensearch_key')
            
            # 2. Set upload_type if missing (default to 'http' for existing files)
            if not case_file.upload_type:
                case_file.upload_type = 'http'
                changes_made.append('upload_type')
            
            # 3. Calculate sigma_event_count
            sigma_event_count = session.query(SigmaViolation.event_id)\
                .filter_by(file_id=case_file.id)\
                .distinct()\
                .count()
            
            if case_file.sigma_event_count != sigma_event_count:
                case_file.sigma_event_count = sigma_event_count
                changes_made.append(f'sigma_event_count={sigma_event_count}')
            
            # 4. Calculate ioc_event_count
            ioc_event_count = session.query(IOCMatch.event_id)\
                .filter_by(case_id=case.id, file_id=case_file.id)\
                .join(IOCMatch.ioc)\
                .filter(IOC.is_active == True)\
                .distinct()\
                .count()
            
            if case_file.ioc_event_count != ioc_event_count:
                case_file.ioc_event_count = ioc_event_count
                changes_made.append(f'ioc_event_count={ioc_event_count}')
            
            if changes_made:
                print(f"      Updated: {', '.join(changes_made)}")
                session.commit()
            else:
                print(f"      Already up-to-date")
        
        # Update case-level aggregates
        print(f"  Updating case-level aggregates...")
        aggregates = session.query(
            func.count(CaseFile.id).label('total_files'),
            func.coalesce(func.sum(CaseFile.event_count), 0).label('total_events'),
            func.coalesce(func.sum(CaseFile.ioc_event_count), 0).label('total_events_with_iocs'),
            func.coalesce(func.sum(CaseFile.sigma_event_count), 0).label('total_events_with_sigma')
        ).filter(
            CaseFile.case_id == case.id,
            CaseFile.is_deleted == False,
            CaseFile.is_hidden == False
        ).first()
        
        case.total_files = aggregates.total_files or 0
        case.total_events = aggregates.total_events or 0
        case.total_events_with_iocs = aggregates.total_events_with_iocs or 0
        case.total_events_with_sigma = aggregates.total_events_with_sigma or 0
        
        session.commit()
        
        print(f"  ✓ Case aggregates: {case.total_files} files, {case.total_events} events, "
              f"{case.total_events_with_sigma} with SIGMA, {case.total_events_with_iocs} with IOCs")
    
    print("\n" + "="*80)
    print("✓ Backfill completed successfully!")
    print("="*80 + "\n")
    
    print("📝 Summary:")
    print(f"  Cases processed: {total_cases}")
    print(f"  All statistics populated")
    print("\n⚠️  IMPORTANT: Restart caseScope services:")
    print("   sudo systemctl restart casescope-web")
    print("   sudo systemctl restart casescope-worker\n")

except Exception as e:
    print(f"\n❌ Backfill failed: {e}")
    import traceback
    traceback.print_exc()
    session.rollback()
    sys.exit(1)
finally:
    session.close()

print("Backfill script completed.")

