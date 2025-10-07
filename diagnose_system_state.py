#!/usr/bin/env python3
"""
Comprehensive System State Diagnostic
Checks database vs OpenSearch consistency
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from main import app, db, CaseFile, Case
from opensearchpy import OpenSearch, RequestsHttpConnection

# OpenSearch client
es = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_compress=True,
    use_ssl=False,
    verify_certs=False,
    ssl_assert_hostname=False,
    ssl_show_warn=False,
    connection_class=RequestsHttpConnection,
    timeout=5
)

def make_index_name(case_id, filename):
    """Generate OpenSearch index name"""
    import os
    name = os.path.splitext(filename)[0]
    name = name.replace('%', '_').replace(' ', '_').replace('-', '_')
    name = name.lower()
    return f"case{case_id}_{name[:100]}"

def check_system_state(case_id=2):
    """Check database vs OpenSearch consistency for a case"""
    
    with app.app_context():
        case = db.session.get(Case, case_id)
        if not case:
            print(f"ERROR: Case {case_id} not found")
            return
        
        print("="*80)
        print(f"SYSTEM STATE DIAGNOSTIC - Case: {case.name} (ID: {case_id})")
        print("="*80)
        print()
        
        # Get all files for this case
        files = db.session.query(CaseFile).filter_by(case_id=case_id, is_deleted=False).all()
        
        print(f"Total files in database: {len(files)}")
        print()
        
        # Check each file
        db_says_indexed = []
        indices_exist = []
        indices_missing = []
        never_indexed = []
        
        for f in files:
            index_name = make_index_name(f.case_id, f.original_filename)
            exists = es.indices.exists(index=index_name)
            
            if f.is_indexed:
                db_says_indexed.append(f)
                if exists:
                    indices_exist.append((f, index_name))
                else:
                    indices_missing.append((f, index_name))
            else:
                never_indexed.append(f)
        
        # Summary
        print("SUMMARY:")
        print(f"  Database says 'is_indexed=True': {len(db_says_indexed)}")
        print(f"  OpenSearch indices actually exist: {len(indices_exist)}")
        print(f"  Mismatch (DB says indexed but index missing): {len(indices_missing)}")
        print(f"  Never indexed (is_indexed=False): {len(never_indexed)}")
        print()
        
        # Details of mismatches
        if indices_missing:
            print("="*80)
            print(f"MISMATCH: {len(indices_missing)} files marked as indexed but indices don't exist:")
            print("="*80)
            for f, idx in indices_missing[:10]:  # Show first 10
                print(f"  • {f.original_filename}")
                print(f"    Status: {f.indexing_status}")
                print(f"    Events: {f.event_count or 0}")
                print(f"    Expected index: {idx}")
                print()
        
        # Files that are actually indexed
        if indices_exist:
            print("="*80)
            print(f"CORRECTLY INDEXED: {len(indices_exist)} files have matching indices:")
            print("="*80)
            for f, idx in indices_exist[:5]:  # Show first 5
                # Get index stats
                try:
                    stats = es.count(index=idx)
                    doc_count = stats['count']
                    print(f"  • {f.original_filename}")
                    print(f"    DB event_count: {f.event_count or 0}, OpenSearch docs: {doc_count}")
                except:
                    print(f"  • {f.original_filename} (error getting stats)")
            print()
        
        # Recommendations
        print("="*80)
        print("RECOMMENDATIONS:")
        print("="*80)
        if indices_missing:
            print(f"1. {len(indices_missing)} files need re-indexing (DB says indexed but indices gone)")
            print("   → Use 'Re-index All Files' button to recreate indices")
            print()
        if never_indexed:
            print(f"2. {len(never_indexed)} files were never indexed")
            print("   → Check why indexing failed or was never triggered")
            print()
        if len(indices_exist) == len(db_says_indexed):
            print("✅ All indexed files have matching OpenSearch indices - system is consistent!")
        print("="*80)

if __name__ == '__main__':
    check_system_state(case_id=2)

