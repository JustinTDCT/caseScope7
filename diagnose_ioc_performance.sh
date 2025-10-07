#!/bin/bash

echo "=== CHECKING CURRENT TASK EXECUTION ==="
echo ""

echo "1. What tasks are running RIGHT NOW:"
sudo journalctl -u casescope-worker --since "1 minute ago" --no-pager | grep "TASK START\|V8.0\|IOC HUNT" | tail -15

echo ""
echo "2. How many database queries happening:"
sudo journalctl -u casescope-worker --since "30 seconds ago" --no-pager | grep -c "SELECT\|INSERT\|UPDATE" || echo "0"

echo ""
echo "3. Files actively processing:"
cd /opt/casescope/app && sudo -u casescope /opt/casescope/venv/bin/python3 << 'PYTHON'
import sys
sys.path.insert(0, '/opt/casescope/app')
from main import app, db, CaseFile

with app.app_context():
    active = db.session.query(CaseFile).filter(
        CaseFile.indexing_status.in_(['Estimating', 'Indexing', 'SIGMA Hunting', 'IOC Hunting'])
    ).count()
    print(f"Files actively processing: {active}")
    
    queued = db.session.query(CaseFile).filter_by(indexing_status='Queued').count()
    print(f"Files queued: {queued}")
    
    completed = db.session.query(CaseFile).filter_by(indexing_status='Completed').count()
    print(f"Files completed: {completed}")
PYTHON

echo ""
echo "4. Redis queue size:"
redis-cli LLEN celery

echo ""
echo "5. OpenSearch health:"
curl -s http://localhost:9200/_cluster/health | python3 -c "import sys, json; d=json.load(sys.stdin); print(f\"Status: {d['status']}, Active shards: {d['active_shards']}/{d['active_shards']+d['unassigned_shards']}\")"

echo ""
echo "6. Check if OLD tasks are still running (should be v8.0):"
sudo journalctl -u casescope-worker --since "2 minutes ago" --no-pager | grep -E "hunt_iocs_for_file|process_file_complete" | head -5

