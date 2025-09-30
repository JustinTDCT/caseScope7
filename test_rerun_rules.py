#!/usr/bin/env python3
"""
Test Re-run Rules Process - Emulates clicking the Re-run Rules button
This script replicates EXACTLY what happens when you click Re-run Rules in the UI
"""

import sys
import os
import time

# Add app directory to path
sys.path.insert(0, '/opt/casescope/app')

print("="*80)
print("RE-RUN RULES FULL PROCESS TEST")
print("="*80)
print()

# File to test
FILE_ID = 3

print(f"Testing Re-run Rules for file ID: {FILE_ID}")
print()

# STEP 1: Import main.py (this is what web service does)
print("[STEP 1] Importing main.py (web application)...")
try:
    from main import app, db, CaseFile, SigmaViolation, celery_app
    print("✓ main.py imported successfully")
    print(f"  celery_app exists: {celery_app is not None}")
    if celery_app:
        print(f"  celery_app type: {type(celery_app)}")
        print(f"  celery_app broker: {celery_app.conf.broker_url}")
        print(f"  celery_app backend: {celery_app.conf.result_backend}")
        print(f"  celery_app registered tasks: {list(celery_app.tasks.keys())}")
    print()
except Exception as e:
    print(f"✗ ERROR importing main.py: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# STEP 2: Check file in database
print("[STEP 2] Checking file in database...")
with app.app_context():
    try:
        case_file = CaseFile.query.get(FILE_ID)
        if not case_file:
            print(f"✗ ERROR: File ID {FILE_ID} not found in database")
            sys.exit(1)
        
        print(f"✓ File found in database:")
        print(f"  ID: {case_file.id}")
        print(f"  Filename: {case_file.original_filename}")
        print(f"  Case ID: {case_file.case_id}")
        print(f"  Status: {case_file.indexing_status}")
        print(f"  Events: {case_file.event_count}")
        print(f"  Current violations: {case_file.violation_count}")
        print()
    except Exception as e:
        print(f"✗ ERROR querying database: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

# STEP 3: Delete existing violations (this is what the route does)
print("[STEP 3] Deleting existing SIGMA violations for this file...")
with app.app_context():
    try:
        existing_violations = SigmaViolation.query.filter_by(file_id=FILE_ID).all()
        print(f"  Found {len(existing_violations)} existing violations")
        
        for violation in existing_violations:
            db.session.delete(violation)
        
        db.session.commit()
        print(f"✓ Deleted {len(existing_violations)} existing violations")
        print()
    except Exception as e:
        print(f"✗ ERROR deleting violations: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

# STEP 4: Reset file status (this is what the route does)
print("[STEP 4] Resetting file status to 'Running Rules'...")
with app.app_context():
    try:
        case_file = CaseFile.query.get(FILE_ID)
        case_file.indexing_status = 'Running Rules'
        case_file.violation_count = 0
        db.session.commit()
        print(f"✓ Status set to: {case_file.indexing_status}")
        print()
    except Exception as e:
        print(f"✗ ERROR updating status: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

# STEP 5: Generate index name (this is what the route does)
print("[STEP 5] Generating OpenSearch index name...")
try:
    name = os.path.splitext(case_file.original_filename)[0]
    name = name.replace('%', '_').replace(' ', '_').replace('-', '_').lower()[:100]
    index_name = f"case{case_file.case_id}_{name}"
    print(f"✓ Index name: {index_name}")
    print()
except Exception as e:
    print(f"✗ ERROR generating index name: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# STEP 6: Queue Celery task (this is what the route does)
print("[STEP 6] Queueing Celery task (EXACTLY as the route does)...")
try:
    if not celery_app:
        print("✗ ERROR: celery_app is None!")
        sys.exit(1)
    
    print(f"  celery_app exists: True")
    print(f"  celery_app broker: {celery_app.conf.broker_url}")
    print(f"  celery_app backend: {celery_app.conf.result_backend}")
    print(f"  Task name: 'tasks.process_sigma_rules'")
    print(f"  Arguments: [{FILE_ID}, '{index_name}']")
    print()
    
    # Create signature and apply async (EXACTLY as main.py does)
    from celery import signature
    print("  Creating signature...")
    sig = signature('tasks.process_sigma_rules', args=[FILE_ID, index_name], app=celery_app)
    print(f"  ✓ Signature created: {sig}")
    print(f"    Signature type: {type(sig)}")
    print(f"    Signature name: {sig.name}")
    print(f"    Signature args: {sig.args}")
    print()
    
    print("  Calling apply_async()...")
    task = sig.apply_async()
    print(f"  ✓ Task object created: {task}")
    print(f"    Task ID: {task.id}")
    print(f"    Task state: {task.state}")
    print(f"    Task ready: {task.ready()}")
    print()
    
except Exception as e:
    print(f"✗ ERROR queueing task: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# STEP 7: Check Redis queue
print("[STEP 7] Checking Redis queue...")
try:
    import redis
    r = redis.Redis(host='localhost', port=6379, db=0)
    
    print("  Connecting to Redis...")
    r.ping()
    print("  ✓ Connected to Redis")
    
    queue_length = r.llen('celery')
    print(f"  Queue 'celery' length: {queue_length}")
    
    if queue_length == 0:
        print("  ✗ WARNING: Queue is empty! Task was not queued properly!")
    else:
        print(f"  ✓ SUCCESS: {queue_length} task(s) in queue")
        
        # Peek at the queue
        items = r.lrange('celery', 0, -1)
        print(f"  Queue contains {len(items)} item(s)")
        for i, item in enumerate(items):
            print(f"    Item {i+1}: {item[:200]}...")
    print()
    
except Exception as e:
    print(f"✗ ERROR checking Redis: {e}")
    import traceback
    traceback.print_exc()

# STEP 8: Check task metadata in Redis
print("[STEP 8] Checking task metadata in Redis...")
try:
    import redis
    r = redis.Redis(host='localhost', port=6379, db=0)
    
    meta_key = f"celery-task-meta-{task.id}"
    print(f"  Looking for key: {meta_key}")
    
    if r.exists(meta_key):
        print(f"  ✓ Metadata exists")
        meta = r.get(meta_key)
        print(f"    Metadata: {meta[:200]}...")
    else:
        print(f"  ✗ Metadata not found")
    print()
    
except Exception as e:
    print(f"✗ ERROR checking metadata: {e}")
    import traceback
    traceback.print_exc()

# STEP 9: Wait and monitor worker
print("[STEP 9] Monitoring worker for 10 seconds...")
print("  (Watch for worker to pick up the task)")
print()

import subprocess
for i in range(10):
    print(f"  Waiting... {i+1}/10 seconds")
    time.sleep(1)
    
    # Check worker logs
    try:
        result = subprocess.run(
            ['journalctl', '-u', 'casescope-worker', '-n', '5', '--no-pager'],
            capture_output=True,
            text=True
        )
        
        if 'process_sigma_rules' in result.stdout or 'TASK START' in result.stdout:
            print("\n  ✓✓✓ WORKER PICKED UP TASK! ✓✓✓")
            print("  Recent worker logs:")
            print(result.stdout)
            break
    except:
        pass

print()

# STEP 10: Check final status
print("[STEP 10] Checking final status...")
with app.app_context():
    try:
        case_file = CaseFile.query.get(FILE_ID)
        print(f"  Status: {case_file.indexing_status}")
        print(f"  Violations: {case_file.violation_count}")
        
        if case_file.indexing_status == 'Running Rules':
            print("  ⚠ Still 'Running Rules' - task may not have completed yet")
        elif case_file.indexing_status == 'Completed':
            print("  ✓ Completed successfully!")
        else:
            print(f"  ? Unknown status: {case_file.indexing_status}")
    except Exception as e:
        print(f"✗ ERROR checking status: {e}")

print()
print("="*80)
print("TEST COMPLETE")
print("="*80)
print()
print("If queue length was 0, the problem is in task serialization/queueing.")
print("If queue had items but worker didn't process, the problem is in worker setup.")
print("Check the output above to identify where the process fails.")
print()
