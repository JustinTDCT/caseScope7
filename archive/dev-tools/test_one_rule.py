#!/usr/bin/env python3
"""
Test ONE SIGMA rule manually to see if matching works
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from opensearchpy import OpenSearch
from sigma.collection import SigmaCollection
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation
from tasks import CASESCOPE_FIELD_MAPPING
import json

# Connect to OpenSearch
client = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_compress=True,
    use_ssl=False,
    verify_certs=False
)

print("="*80)
print("MANUAL SIGMA RULE TEST")
print("="*80)
print()

# Get index
indices = client.cat.indices(format='json')
case_indices = [idx['index'] for idx in indices if idx['index'].startswith('case')]
if not case_indices:
    print("❌ No indices!")
    sys.exit(1)

test_index = case_indices[0]
print(f"Using index: {test_index}")
print()

# Create a VERY simple test rule
test_rule = """
title: Test Rule - Any PowerShell Event
status: test
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
    condition: selection
level: low
"""

print("Test SIGMA rule:")
print(test_rule)
print()

# Set up SIGMA backend with our field mapping
print("Setting up SIGMA backend with caseScope field mapping...")
field_mapping = FieldMappingTransformation(CASESCOPE_FIELD_MAPPING)
pipeline = ProcessingPipeline(
    name="casescope-pipeline",
    priority=20,
    items=[
        ProcessingItem(
            identifier="field-mapping",
            transformation=field_mapping,
            rule_conditions=[]
        )
    ]
)
backend = OpensearchLuceneBackend(processing_pipeline=pipeline)
print("✓ Backend created")
print()

# Convert SIGMA to OpenSearch query
print("Converting SIGMA rule to OpenSearch query...")
try:
    sigma_collection = SigmaCollection.from_yaml(test_rule)
    queries = backend.convert(sigma_collection)
    
    if isinstance(queries, list):
        opensearch_query = queries[0] if queries else None
    else:
        opensearch_query = queries
    
    print("✓ Conversion successful")
    print()
    print("Generated OpenSearch query:")
    print(json.dumps(opensearch_query, indent=2))
    print()
    
except Exception as e:
    print(f"❌ Conversion failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Execute the query
print("Executing query against OpenSearch...")
try:
    search_body = {
        "query": opensearch_query,
        "size": 5  # Get a few samples
    }
    
    response = client.search(
        index=test_index,
        body=search_body
    )
    
    hits = response['hits']['total']['value']
    print(f"✓ Query executed successfully")
    print(f"✓ MATCHES FOUND: {hits}")
    print()
    
    if hits > 0:
        print(f"Sample matched events (showing {len(response['hits']['hits'])}):")
        for i, hit in enumerate(response['hits']['hits'], 1):
            event = hit['_source']
            event_id = event.get('System.EventID.#text', event.get('System.EventID', 'N/A'))
            computer = event.get('System.Computer', 'N/A')
            print(f"  {i}. EventID={event_id}, Computer={computer}")
    else:
        print("❌ NO MATCHES - Let's check if EventID 4104 exists at all:")
        print()
        
        # Try direct search
        direct_search = {
            "query": {
                "match": {
                    "System.EventID.#text": "4104"
                }
            },
            "size": 1
        }
        
        direct_response = client.search(index=test_index, body=direct_search)
        direct_hits = direct_response['hits']['total']['value']
        
        if direct_hits > 0:
            print(f"✓ Direct search found {direct_hits} EventID 4104 events")
            print("❌ PROBLEM: SIGMA query doesn't match but direct search does!")
            print("   This means the field mapping is broken.")
            print()
            sample = direct_response['hits']['hits'][0]['_source']
            print("Sample event structure:")
            for key in sorted(sample.keys())[:20]:
                print(f"  {key}: {str(sample[key])[:50]}")
        else:
            print("❌ Direct search also found 0 events")
            print("   EventID 4104 doesn't exist in this index")
            
except Exception as e:
    print(f"❌ Query execution failed: {e}")
    import traceback
    traceback.print_exc()

print()
print("="*80)
print("TEST COMPLETE")
print("="*80)
