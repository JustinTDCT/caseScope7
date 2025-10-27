#!/usr/bin/env python3
"""
Verification script to ensure caseScope is in a clean state after "Delete All Files"
Checks database tables, OpenSearch indices, physical files, and Redis state.

Usage: python3 verify_clean_state.py [case_id]
"""

import os
import sys
import sqlite3
from opensearchpy import OpenSearch
import redis

# Configuration
DB_PATH = '/opt/casescope/data/casescope.db'  # v9.5.7 fix: correct path
UPLOAD_BASE = '/opt/casescope/uploads'
OPENSEARCH_HOST = 'localhost'
OPENSEARCH_PORT = 9200
REDIS_HOST = 'localhost'
REDIS_PORT = 6379

def check_database(case_id=None):
    """Check all relevant database tables for residual data."""
    print("=" * 80)
    print("DATABASE VERIFICATION")
    print("=" * 80)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Build WHERE clause for case filtering
    where_case = f"WHERE case_id = {case_id}" if case_id else ""
    
    # Check CaseFile table
    cursor.execute(f"SELECT COUNT(*) FROM case_file {where_case}")
    file_count = cursor.fetchone()[0]
    print(f"\n📁 CaseFile table: {file_count} records")
    if file_count > 0:
        print("   ⚠️  WARNING: Should be 0 after Delete All Files")
        cursor.execute(f"""
            SELECT id, case_id, original_filename, indexing_status, file_size
            FROM case_file {where_case}
            LIMIT 5
        """)
        print("   First 5 records:")
        for row in cursor.fetchall():
            print(f"      ID={row[0]}, Case={row[1]}, File={row[2]}, Status={row[3]}, Size={row[4]}")
    else:
        print("   ✓ Clean (0 records)")
    
    # Check SkippedFile table
    cursor.execute(f"SELECT COUNT(*) FROM skipped_file {where_case}")
    skipped_count = cursor.fetchone()[0]
    print(f"\n📋 SkippedFile table: {skipped_count} records")
    if skipped_count > 0:
        print("   ⚠️  WARNING: Should be 0 after Delete All Files")
        cursor.execute(f"""
            SELECT id, case_id, filename, skip_reason, file_size
            FROM skipped_file {where_case}
            LIMIT 5
        """)
        print("   First 5 records:")
        for row in cursor.fetchall():
            print(f"      ID={row[0]}, Case={row[1]}, File={row[2]}, Reason={row[3]}, Size={row[4]}")
    else:
        print("   ✓ Clean (0 records)")
    
    # Check SigmaViolation table
    cursor.execute(f"SELECT COUNT(*) FROM sigma_violation {where_case}")
    sigma_count = cursor.fetchone()[0]
    print(f"\n⚠️  SigmaViolation table: {sigma_count} records")
    if sigma_count > 0:
        print("   ⚠️  WARNING: Should be 0 after Delete All Files")
    else:
        print("   ✓ Clean (0 records)")
    
    # Check IOCMatch table
    cursor.execute(f"SELECT COUNT(*) FROM ioc_match {where_case}")
    ioc_count = cursor.fetchone()[0]
    print(f"\n🎯 IOCMatch table: {ioc_count} records")
    if ioc_count > 0:
        print("   ⚠️  WARNING: Should be 0 after Delete All Files")
    else:
        print("   ✓ Clean (0 records)")
    
    # Check EventTag table
    if case_id:
        cursor.execute(f"""
            SELECT COUNT(*) FROM event_tag 
            WHERE event_id LIKE 'case{case_id}_%'
        """)
    else:
        cursor.execute("SELECT COUNT(*) FROM event_tag")
    tag_count = cursor.fetchone()[0]
    print(f"\n🏷️  EventTag table: {tag_count} records")
    if tag_count > 0:
        print("   ⚠️  WARNING: Should be 0 after Delete All Files")
    else:
        print("   ✓ Clean (0 records)")
    
    # Check Case aggregates
    if case_id:
        cursor.execute(f"""
            SELECT id, name, total_files, total_events, 
                   total_events_with_IOCs, total_events_with_SIGMA_violations
            FROM "case" WHERE id = {case_id}
        """)
    else:
        cursor.execute("""
            SELECT id, name, total_files, total_events, 
                   total_events_with_IOCs, total_events_with_SIGMA_violations
            FROM "case"
        """)
    
    print(f"\n📊 Case Statistics:")
    for row in cursor.fetchall():
        case_id_db, name, total_files, total_events, ioc_events, sigma_events = row
        print(f"\n   Case {case_id_db}: {name}")
        print(f"      Total Files: {total_files}")
        print(f"      Total Events: {total_events}")
        print(f"      IOC Events: {ioc_events}")
        print(f"      SIGMA Events: {sigma_events}")
        
        if total_files > 0 or total_events > 0 or ioc_events > 0 or sigma_events > 0:
            print("      ⚠️  WARNING: All should be 0 after Delete All Files")
        else:
            print("      ✓ Clean (all zeros)")
    
    conn.close()


def check_opensearch(case_id=None):
    """Check OpenSearch for residual indices."""
    print("\n" + "=" * 80)
    print("OPENSEARCH VERIFICATION")
    print("=" * 80)
    
    try:
        client = OpenSearch(
            hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            timeout=30
        )
        
        # Get all indices
        indices = client.cat.indices(format='json')
        
        # Filter for case indices
        if case_id:
            case_indices = [idx for idx in indices if idx['index'].startswith(f'case_{case_id}_')]
        else:
            case_indices = [idx for idx in indices if idx['index'].startswith('case_')]
        
        print(f"\n🔍 OpenSearch Indices: {len(case_indices)} found")
        
        if case_indices:
            print("   ⚠️  WARNING: Should be 0 indices after Delete All Files")
            print("\n   Indices found:")
            for idx in case_indices[:10]:  # Show first 10
                docs = idx.get('docs.count', '0')
                size = idx.get('store.size', '0b')
                print(f"      {idx['index']}: {docs} docs, {size}")
            if len(case_indices) > 10:
                print(f"      ... and {len(case_indices) - 10} more")
        else:
            print("   ✓ Clean (0 indices)")
            
    except Exception as e:
        print(f"   ✗ ERROR: Could not connect to OpenSearch: {e}")


def check_physical_files(case_id=None):
    """Check for orphaned physical files on disk."""
    print("\n" + "=" * 80)
    print("PHYSICAL FILES VERIFICATION")
    print("=" * 80)
    
    if case_id:
        upload_dirs = [os.path.join(UPLOAD_BASE, str(case_id))]
    else:
        upload_dirs = [os.path.join(UPLOAD_BASE, d) for d in os.listdir(UPLOAD_BASE) 
                      if os.path.isdir(os.path.join(UPLOAD_BASE, d)) and d.isdigit()]
    
    total_files = 0
    total_size = 0
    
    for upload_dir in upload_dirs:
        if not os.path.exists(upload_dir):
            continue
            
        case_num = os.path.basename(upload_dir)
        files = []
        
        for root, dirs, filenames in os.walk(upload_dir):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                try:
                    size = os.path.getsize(filepath)
                    files.append((filepath, size))
                    total_size += size
                except:
                    pass
        
        total_files += len(files)
        
        if files:
            print(f"\n📂 Case {case_num}: {len(files)} files, {total_size / 1024 / 1024:.2f} MB")
            print("   ⚠️  WARNING: Should be 0 files after Delete All Files")
            print("   First 5 files:")
            for filepath, size in files[:5]:
                print(f"      {filepath} ({size / 1024 / 1024:.2f} MB)")
        else:
            print(f"\n📂 Case {case_num}: ✓ Clean (0 files)")
    
    if total_files == 0:
        print(f"\n✓ All upload directories clean")
    else:
        print(f"\n⚠️  TOTAL: {total_files} orphaned files, {total_size / 1024 / 1024:.2f} MB")


def check_redis(case_id=None):
    """Check Redis for residual task state."""
    print("\n" + "=" * 80)
    print("REDIS VERIFICATION")
    print("=" * 80)
    
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
        
        # Check Celery task queues
        queues = ['celery', 'celery:tasks']
        total_tasks = 0
        
        for queue in queues:
            try:
                length = r.llen(queue)
                total_tasks += length
                if length > 0:
                    print(f"\n📮 Queue '{queue}': {length} pending tasks")
                    print("   ⚠️  WARNING: Tasks may be stuck")
                else:
                    print(f"\n📮 Queue '{queue}': ✓ Clean (0 tasks)")
            except:
                pass
        
        # Check for casescope-specific keys
        keys = r.keys('casescope:*')
        if keys:
            print(f"\n🔑 Redis keys: {len(keys)} found")
            for key in keys[:5]:
                print(f"      {key}")
            if len(keys) > 5:
                print(f"      ... and {len(keys) - 5} more")
        else:
            print(f"\n🔑 Redis keys: ✓ Clean (0 keys)")
            
    except Exception as e:
        print(f"   ✗ ERROR: Could not connect to Redis: {e}")


def cleanup_all(case_id=None):
    """Perform cleanup of all residual data (DANGEROUS!)."""
    print("\n" + "=" * 80)
    print("⚠️  CLEANUP MODE - THIS WILL DELETE DATA!")
    print("=" * 80)
    
    response = input("\nAre you sure you want to cleanup all residual data? (type 'YES' to confirm): ")
    if response != 'YES':
        print("Cleanup cancelled.")
        return
    
    # Database cleanup
    print("\n1. Cleaning database...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    where_case = f"WHERE case_id = {case_id}" if case_id else ""
    
    cursor.execute(f"DELETE FROM case_file {where_case}")
    deleted_files = cursor.rowcount
    print(f"   Deleted {deleted_files} CaseFile records")
    
    cursor.execute(f"DELETE FROM skipped_file {where_case}")
    deleted_skipped = cursor.rowcount
    print(f"   Deleted {deleted_skipped} SkippedFile records")
    
    cursor.execute(f"DELETE FROM sigma_violation {where_case}")
    deleted_sigma = cursor.rowcount
    print(f"   Deleted {deleted_sigma} SigmaViolation records")
    
    cursor.execute(f"DELETE FROM ioc_match {where_case}")
    deleted_ioc = cursor.rowcount
    print(f"   Deleted {deleted_ioc} IOCMatch records")
    
    if case_id:
        cursor.execute(f"DELETE FROM event_tag WHERE event_id LIKE 'case{case_id}_%'")
    else:
        cursor.execute("DELETE FROM event_tag")
    deleted_tags = cursor.rowcount
    print(f"   Deleted {deleted_tags} EventTag records")
    
    # Reset case statistics
    if case_id:
        cursor.execute(f"""
            UPDATE "case" 
            SET total_files = 0, total_events = 0, 
                total_events_with_IOCs = 0, total_events_with_SIGMA_violations = 0
            WHERE id = {case_id}
        """)
    else:
        cursor.execute("""
            UPDATE "case" 
            SET total_files = 0, total_events = 0, 
                total_events_with_IOCs = 0, total_events_with_SIGMA_violations = 0
        """)
    
    conn.commit()
    conn.close()
    print("   ✓ Database cleaned")
    
    # OpenSearch cleanup
    print("\n2. Cleaning OpenSearch indices...")
    try:
        client = OpenSearch(
            hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            timeout=30
        )
        
        indices = client.cat.indices(format='json')
        if case_id:
            case_indices = [idx['index'] for idx in indices if idx['index'].startswith(f'case_{case_id}_')]
        else:
            case_indices = [idx['index'] for idx in indices if idx['index'].startswith('case_')]
        
        for index in case_indices:
            client.indices.delete(index=index)
            print(f"   Deleted index: {index}")
        
        print(f"   ✓ Deleted {len(case_indices)} indices")
    except Exception as e:
        print(f"   ✗ OpenSearch cleanup failed: {e}")
    
    # Physical files cleanup
    print("\n3. Cleaning physical files...")
    if case_id:
        upload_dirs = [os.path.join(UPLOAD_BASE, str(case_id))]
    else:
        upload_dirs = [os.path.join(UPLOAD_BASE, d) for d in os.listdir(UPLOAD_BASE) 
                      if os.path.isdir(os.path.join(UPLOAD_BASE, d)) and d.isdigit()]
    
    deleted_files = 0
    for upload_dir in upload_dirs:
        if os.path.exists(upload_dir):
            import shutil
            try:
                shutil.rmtree(upload_dir)
                os.makedirs(upload_dir, exist_ok=True)
                os.chown(upload_dir, 1000, 1000)  # casescope user
                print(f"   Cleaned: {upload_dir}")
                deleted_files += 1
            except Exception as e:
                print(f"   ✗ Failed to clean {upload_dir}: {e}")
    
    print(f"   ✓ Cleaned {deleted_files} upload directories")
    
    print("\n" + "=" * 80)
    print("✓ CLEANUP COMPLETE")
    print("=" * 80)


if __name__ == '__main__':
    case_id = None
    cleanup_mode = False
    
    # Parse arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == '--cleanup':
            cleanup_mode = True
            if len(sys.argv) > 2:
                case_id = int(sys.argv[2])
        else:
            case_id = int(sys.argv[1])
    
    print("\n" + "=" * 80)
    print("caseScope CLEAN STATE VERIFICATION")
    print("=" * 80)
    if case_id:
        print(f"Checking Case ID: {case_id}")
    else:
        print("Checking: ALL CASES")
    print("=" * 80)
    
    if cleanup_mode:
        cleanup_all(case_id)
    else:
        check_database(case_id)
        check_opensearch(case_id)
        check_physical_files(case_id)
        check_redis(case_id)
        
        print("\n" + "=" * 80)
        print("VERIFICATION COMPLETE")
        print("=" * 80)
        print("\nTo perform cleanup, run:")
        if case_id:
            print(f"  sudo python3 verify_clean_state.py --cleanup {case_id}")
        else:
            print(f"  sudo python3 verify_clean_state.py --cleanup")
        print("\n⚠️  WARNING: Cleanup will permanently delete all residual data!")
        print("=" * 80 + "\n")

