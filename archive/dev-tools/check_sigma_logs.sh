#!/bin/bash

echo "================================================================================"
echo "SIGMA RULE EXECUTION DIAGNOSTICS"
echo "================================================================================"
echo ""

echo "1. Checking for recent SIGMA task execution in worker logs:"
echo "--------------------------------------------------------------------------------"
sudo journalctl -u casescope-worker --since "10 minutes ago" | grep -i "sigma\|rule\|violation" | tail -50

echo ""
echo "2. Checking for task completion:"
echo "--------------------------------------------------------------------------------"
sudo journalctl -u casescope-worker --since "10 minutes ago" | grep -i "completed\|success\|failed" | tail -20

echo ""
echo "3. Checking for OpenSearch query errors:"
echo "--------------------------------------------------------------------------------"
sudo journalctl -u casescope-worker --since "10 minutes ago" | grep -i "error\|exception\|failed" | tail -20

echo ""
echo "4. Quick database check:"
echo "--------------------------------------------------------------------------------"
sudo -u casescope /opt/casescope/venv/bin/python3 << 'PYEOF'
import sys
sys.path.insert(0, '/opt/casescope/app')
from main import app, db, SigmaRule, SigmaViolation, CaseFile

with app.app_context():
    enabled = SigmaRule.query.filter_by(is_enabled=True).count()
    violations = SigmaViolation.query.count()
    files = CaseFile.query.filter_by(is_indexed=True).all()
    
    print(f"Enabled rules: {enabled}")
    print(f"Total violations: {violations}")
    print(f"Indexed files: {len(files)}")
    
    for f in files:
        print(f"  {f.original_filename}: status={f.indexing_status}, events={f.event_count}, violations={f.violation_count}")
PYEOF

echo ""
echo "================================================================================"
echo "Run this for detailed analysis:"
echo "  sudo -u casescope /opt/casescope/venv/bin/python3 /opt/casescope/simple_sigma_test.py"
echo "================================================================================"
