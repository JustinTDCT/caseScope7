#!/usr/bin/env python3
"""
Simple SIGMA matching test - checks if events are indexed and searchable
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from opensearchpy import OpenSearch
import json

# Connect to OpenSearch
client = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_compress=True,
    use_ssl=False,
    verify_certs=False
)

print("="*80)
print("SIMPLE SIGMA DIAGNOSTIC")
print("="*80)
print()

# Get indices
indices = client.cat.indices(format='json')
case_indices = [idx['index'] for idx in indices if idx['index'].startswith('case')]

if not case_indices:
    print("❌ No case indices found!")
    sys.exit(1)

test_index = case_indices[0]
print(f"Testing index: {test_index}")
print()

# Get total events
response = client.count(index=test_index)
total_events = response['count']
print(f"Total events in index: {total_events:,}")
print()

# Get a sample event to see structure
response = client.search(
    index=test_index,
    body={"query": {"match_all": {}}, "size": 1}
)

if response['hits']['total']['value'] == 0:
    print("❌ No events found!")
    sys.exit(1)

sample = response['hits']['hits'][0]['_source']

print("Sample event keys (first 30):")
for i, key in enumerate(sorted(sample.keys())[:30]):
    print(f"  {key}")

print()
print("Checking critical fields:")
print("-"*80)

# Check if we have the fields SIGMA needs
critical_checks = [
    ('System.EventID.#text', 'EventID with #text'),
    ('System.EventID', 'EventID without #text'),
    ('EventData.CommandLine', 'CommandLine'),
    ('EventData.Image', 'Image/Process'),
]

for field, description in critical_checks:
    if field in sample:
        value = sample[field]
        print(f"✓ {description}: {field} = {str(value)[:50]}")
    else:
        print(f"✗ {description}: {field} NOT FOUND")

print()
print("Testing simple queries:")
print("-"*80)

# Test 1: Match all
response = client.search(
    index=test_index,
    body={"query": {"match_all": {}}, "size": 0}
)
print(f"Match all: {response['hits']['total']['value']:,} events")

# Test 2: Search for EventID 4104 (PowerShell)
test_queries = [
    ("System.EventID.#text", "4104"),
    ("System.EventID", "4104"),
    ("EventID", "4104"),
]

for field, value in test_queries:
    try:
        response = client.search(
            index=test_index,
            body={
                "query": {
                    "match": {field: value}
                },
                "size": 0
            }
        )
        count = response['hits']['total']['value']
        if count > 0:
            print(f"✓ {field}:{value} → {count:,} events")
        else:
            print(f"✗ {field}:{value} → 0 events")
    except Exception as e:
        print(f"✗ {field}:{value} → ERROR: {e}")

print()
print("Checking SIGMA rule execution:")
print("-"*80)

# Check database for rules and violations
from main import app, db, SigmaRule, SigmaViolation, CaseFile

with app.app_context():
    total_rules = SigmaRule.query.count()
    enabled_rules = SigmaRule.query.filter_by(is_enabled=True).count()
    total_violations = SigmaViolation.query.count()
    
    print(f"Total SIGMA rules: {total_rules}")
    print(f"Enabled SIGMA rules: {enabled_rules}")
    print(f"Total violations: {total_violations}")
    print()
    
    if enabled_rules > 0:
        print("Sample enabled rules:")
        for rule in SigmaRule.query.filter_by(is_enabled=True).limit(5):
            print(f"  - {rule.title} ({rule.level})")
    
    print()
    
    # Check file status
    files = CaseFile.query.filter_by(is_indexed=True).all()
    print(f"Indexed files: {len(files)}")
    for f in files:
        print(f"  - {f.original_filename}: {f.indexing_status}, {f.event_count:,} events, {f.violation_count} violations")

print()
print("="*80)
print("DIAGNOSIS COMPLETE")
print("="*80)
