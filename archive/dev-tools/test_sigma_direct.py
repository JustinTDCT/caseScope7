#!/usr/bin/env python3
"""
Direct SIGMA rule test - bypasses Celery/web completely
Tests SIGMA rule processing against a specific file
"""

import sys
import os

# Add app directory to path
sys.path.insert(0, '/opt/casescope/app')

print("="*80)
print("DIRECT SIGMA RULE TEST")
print("="*80)
print()

# Import required modules
print("[1/6] Importing modules...")
from main import app, db, CaseFile, SigmaRule, SigmaViolation
from opensearchpy import OpenSearch
from sigma.collection import SigmaCollection
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
import yaml

print("✓ Modules imported successfully")
print()

# File to test
FILE_ID = 3
FILE_PATH = "/opt/casescope/uploads/2/1759186131_ENGINEERING5_Security.evtx"
INDEX_NAME = "case2_engineering5_security"

print(f"[2/6] Checking file...")
print(f"  File ID: {FILE_ID}")
print(f"  Path: {FILE_PATH}")
print(f"  Index: {INDEX_NAME}")

if not os.path.exists(FILE_PATH):
    print(f"✗ ERROR: File not found: {FILE_PATH}")
    sys.exit(1)

print(f"✓ File exists: {os.path.getsize(FILE_PATH)} bytes")
print()

# Connect to OpenSearch
print("[3/6] Connecting to OpenSearch...")
try:
    os_client = OpenSearch(
        hosts=[{'host': 'localhost', 'port': 9200}],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        timeout=30
    )
    
    # Check if index exists
    if not os_client.indices.exists(index=INDEX_NAME):
        print(f"✗ ERROR: Index does not exist: {INDEX_NAME}")
        sys.exit(1)
    
    # Get document count
    count_response = os_client.count(index=INDEX_NAME)
    doc_count = count_response['count']
    print(f"✓ Connected to OpenSearch")
    print(f"  Index: {INDEX_NAME}")
    print(f"  Documents: {doc_count}")
    print()
except Exception as e:
    print(f"✗ ERROR: Failed to connect to OpenSearch: {e}")
    sys.exit(1)

# Get enabled SIGMA rules from database
print("[4/6] Loading enabled SIGMA rules from database...")
with app.app_context():
    enabled_rules = SigmaRule.query.filter_by(enabled=True).all()
    print(f"✓ Found {len(enabled_rules)} enabled rules")
    
    if len(enabled_rules) == 0:
        print("✗ ERROR: No enabled rules found!")
        sys.exit(1)
    
    # Show first 5 rules
    print(f"  Sample rules:")
    for rule in enabled_rules[:5]:
        print(f"    - {rule.title} (Level: {rule.level})")
    print()

# Create SIGMA backend with field mapping
print("[5/6] Setting up SIGMA backend and processing pipeline...")
try:
    # Field mapping for EVTX structure
    field_mappings = {
        'EventID': 'System.EventID',
        'CommandLine': 'EventData.CommandLine',
        'Image': 'EventData.Image',
        'ParentImage': 'EventData.ParentImage',
        'TargetFilename': 'EventData.TargetFilename',
        'User': 'EventData.User',
        'LogonType': 'EventData.LogonType',
        'SourceIp': 'EventData.SourceIp',
        'DestinationIp': 'EventData.DestinationIp',
    }
    
    pipeline = ProcessingPipeline(
        name="evtx-pipeline",
        priority=20,
        items=[
            FieldMappingTransformation(field_mappings)
        ]
    )
    
    backend = OpensearchLuceneBackend(processing_pipeline=pipeline)
    print("✓ Backend configured with field mappings")
    print()
except Exception as e:
    print(f"✗ ERROR: Failed to set up backend: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Process each rule
print("[6/6] Processing SIGMA rules against index...")
violations_found = 0
rules_processed = 0
rules_with_hits = 0

with app.app_context():
    # Clear existing violations for this file
    existing = SigmaViolation.query.filter_by(file_id=FILE_ID).all()
    print(f"  Clearing {len(existing)} existing violations...")
    for v in existing:
        db.session.delete(v)
    db.session.commit()
    
    print(f"  Processing {len(enabled_rules)} rules...")
    print()
    
    for i, rule in enumerate(enabled_rules, 1):
        try:
            # Parse rule YAML
            sigma_rule = SigmaCollection.from_yaml(rule.rule_content)
            
            # Convert to OpenSearch query
            queries = backend.convert(sigma_rule)
            
            # Execute each query
            for query in queries:
                try:
                    # Search OpenSearch
                    search_result = os_client.search(
                        index=INDEX_NAME,
                        body={
                            'query': {
                                'query_string': {
                                    'query': query
                                }
                            },
                            'size': 100  # Limit results
                        }
                    )
                    
                    hits = search_result['hits']['total']['value']
                    
                    if hits > 0:
                        rules_with_hits += 1
                        print(f"  [{i}/{len(enabled_rules)}] ✓ MATCH: {rule.title}")
                        print(f"      Level: {rule.level}, Hits: {hits}")
                        
                        # Create violation records
                        for hit in search_result['hits']['hits']:
                            violation = SigmaViolation(
                                file_id=FILE_ID,
                                rule_id=rule.id,
                                event_id=hit['_source'].get('System', {}).get('EventID', 'Unknown'),
                                timestamp=hit['_source'].get('System', {}).get('@timestamp', ''),
                                details=str(hit['_source'])[:1000]
                            )
                            db.session.add(violation)
                            violations_found += 1
                    
                    rules_processed += 1
                    
                except Exception as search_err:
                    print(f"  [{i}/{len(enabled_rules)}] ✗ ERROR searching: {rule.title}")
                    print(f"      {search_err}")
                    continue
                    
        except Exception as rule_err:
            print(f"  [{i}/{len(enabled_rules)}] ✗ ERROR parsing: {rule.title}")
            print(f"      {rule_err}")
            continue
    
    # Commit all violations
    db.session.commit()
    
    # Update file status
    case_file = CaseFile.query.get(FILE_ID)
    if case_file:
        case_file.violation_count = violations_found
        case_file.indexing_status = 'Completed'
        db.session.commit()
    
    print()
    print("="*80)
    print("RESULTS")
    print("="*80)
    print(f"Rules processed: {rules_processed}/{len(enabled_rules)}")
    print(f"Rules with matches: {rules_with_hits}")
    print(f"Total violations found: {violations_found}")
    print()
    
    if violations_found > 0:
        print("✓ SUCCESS: SIGMA rules are working!")
        print(f"  Check the UI - file ID {FILE_ID} should now show {violations_found} violations")
    else:
        print("⚠ WARNING: No violations found")
        print("  This could mean:")
        print("  - The rules don't match this data")
        print("  - Field mappings need adjustment")
        print("  - The events don't contain suspicious activity")
    print()
