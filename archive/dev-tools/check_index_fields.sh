#!/bin/bash
echo "Checking what fields are actually in the OpenSearch index..."
curl -s "http://localhost:9200/case_2_1759186131_engineering5_security/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 1,
  "query": {"match_all": {}}
}
' | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data['hits']['total']['value'] > 0:
    event = data['hits']['hits'][0]['_source']
    print('Sample event fields:')
    for key in sorted(event.keys())[:50]:
        print(f'  {key}: {str(event[key])[:80]}')
else:
    print('No events found!')
"
