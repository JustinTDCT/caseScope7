#!/usr/bin/env python3
"""
Diagnostic script to check SIGMA rule matching issues
Compares indexed event structure with SIGMA query expectations
"""

import sys
import os
sys.path.insert(0, '/opt/casescope/app')

from opensearchpy import OpenSearch
from sigma.collection import SigmaCollection
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from tasks import CASESCOPE_FIELD_MAPPING
import json

# Initialize OpenSearch client
opensearch_client = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_compress=True,
    use_ssl=False,
    verify_certs=False
)

print("="*80)
print("SIGMA MATCHING DIAGNOSTIC")
print("="*80)
print()

# Get all indices
try:
    indices_response = opensearch_client.cat.indices(format='json')
    case_indices = [idx['index'] for idx in indices_response if idx['index'].startswith('case')]
    
    if not case_indices:
        print("❌ No case indices found!")
        sys.exit(1)
    
    print(f"Found {len(case_indices)} case indices:")
    for idx in case_indices[:5]:
        print(f"  - {idx}")
    print()
    
    # Use the first index for testing
    test_index = case_indices[0]
    print(f"Using test index: {test_index}")
    print()
    
    # Get a sample event
    print("Fetching sample event...")
    response = opensearch_client.search(
        index=test_index,
        body={"query": {"match_all": {}}, "size": 1}
    )
    
    if response['hits']['total']['value'] == 0:
        print("❌ No events in index!")
        sys.exit(1)
    
    sample_event = response['hits']['hits'][0]['_source']
    
    print("Sample event structure:")
    print("-" * 80)
    
    # Show top-level keys
    print("Top-level keys:")
    for key in sorted(sample_event.keys())[:20]:
        value = sample_event[key]
        value_preview = str(value)[:100] if len(str(value)) < 100 else str(value)[:97] + "..."
        print(f"  {key}: {value_preview}")
    
    print()
    print("Looking for SIGMA-relevant fields:")
    print("-" * 80)
    
    # Check specific SIGMA field mappings
    critical_fields = [
        ('EventID', 'System.EventID.#text'),
        ('CommandLine', 'EventData.CommandLine'),
        ('Image', 'EventData.Image'),
        ('Computer', 'System.Computer'),
        ('Provider_Name', 'System.Provider.@Name'),
    ]
    
    for sigma_field, expected_path in critical_fields:
        # Try to find the field in the sample event
        found = False
        found_at = None
        
        # Check exact path
        if expected_path in sample_event:
            found = True
            found_at = expected_path
            value = sample_event[expected_path]
        else:
            # Try variations
            variations = [
                expected_path.replace('.#text', ''),
                expected_path.replace('#text', 'text'),
                expected_path.replace('.@Name', ''),
                expected_path.replace('@Name', 'Name'),
            ]
            for var in variations:
                if var in sample_event:
                    found = True
                    found_at = f"{var} (expected: {expected_path})"
                    value = sample_event[var]
                    break
        
        if found:
            print(f"  ✓ {sigma_field}: FOUND at {found_at}")
            print(f"    Value: {value}")
        else:
            print(f"  ❌ {sigma_field}: NOT FOUND (expected at {expected_path})")
    
    print()
    print("Testing SIGMA query generation:")
    print("-" * 80)
    
    # Create a simple test SIGMA rule
    test_rule_yaml = """
title: Test PowerShell Rule
status: test
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
    condition: selection
"""
    
    try:
        # Create SIGMA backend with our mapping
        field_mapping = FieldMappingTransformation(CASESCOPE_FIELD_MAPPING)
        pipeline = ProcessingPipeline(
            name="casescope-pipeline",
            priority=20,
            items=[
                {
                    "transformation": field_mapping,
                    "rule_conditions": []
                }
            ]
        )
        backend = OpensearchLuceneBackend(processing_pipeline=pipeline)
        
        # Convert the test rule
        sigma_collection = SigmaCollection.from_yaml(test_rule_yaml)
        queries = backend.convert(sigma_collection)
        
        if isinstance(queries, list):
            opensearch_query = queries[0] if queries else None
        else:
            opensearch_query = queries
        
        print("Generated OpenSearch query:")
        print(json.dumps(opensearch_query, indent=2))
        print()
        
        # Execute the query
        search_body = {
            "query": opensearch_query,
            "size": 5
        }
        
        print(f"Searching index {test_index}...")
        search_response = opensearch_client.search(
            index=test_index,
            body=search_body,
            request_timeout=30
        )
        
        hits = search_response['hits']['total']['value']
        print(f"Query returned: {hits} hits")
        
        if hits > 0:
            print("✓ SIGMA query is working!")
            print(f"Sample matched event EventID: {search_response['hits']['hits'][0]['_source'].get('System.EventID.#text', 'N/A')}")
        else:
            print("❌ SIGMA query returned 0 hits")
            print()
            print("Checking if EventID 4104 exists in index...")
            
            # Try direct query
            direct_query = {
                "query": {
                    "match": {
                        "System.EventID.#text": "4104"
                    }
                },
                "size": 1
            }
            
            direct_response = opensearch_client.search(
                index=test_index,
                body=direct_query
            )
            
            if direct_response['hits']['total']['value'] > 0:
                print(f"✓ Found EventID 4104 with direct query! ({direct_response['hits']['total']['value']} events)")
                print("❌ Issue: SIGMA field mapping is not working correctly!")
            else:
                print("❌ EventID 4104 not found in index")
        
    except Exception as e:
        print(f"❌ Error testing SIGMA: {e}")
        import traceback
        traceback.print_exc()

except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()

print()
print("="*80)
print("DIAGNOSIS COMPLETE")
print("="*80)
