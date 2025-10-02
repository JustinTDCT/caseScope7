#!/bin/bash
# Celery/Redis Diagnostic Tool for caseScope

echo "=================================================================="
echo "caseScope Celery/Redis Diagnostic Tool"
echo "=================================================================="
echo ""

echo "1. Checking Redis service status..."
systemctl is-active redis-server || systemctl is-active redis
echo ""

echo "2. Checking Redis connectivity..."
redis-cli ping
echo ""

echo "3. Checking Redis queue 'celery'..."
echo "Queue length:"
redis-cli LLEN celery
echo ""

echo "4. Checking all Redis keys..."
redis-cli KEYS '*'
echo ""

echo "5. Checking Redis info..."
redis-cli INFO | grep -E "connected_clients|used_memory_human"
echo ""

echo "6. Checking worker service status..."
systemctl status casescope-worker --no-pager -l | head -20
echo ""

echo "7. Checking worker process..."
ps aux | grep -E "celery.*worker" | grep -v grep
echo ""

echo "8. Testing task queueing from Python..."
cd /opt/casescope/app
source /opt/casescope/venv/bin/activate
python3 << 'PYEOF'
import sys
print("Python path:", sys.path)

try:
    from celery import Celery
    print("✓ Celery imported successfully")
    
    # Create app
    app = Celery('test', broker='redis://localhost:6379/0', backend='redis://localhost:6379/0')
    print("✓ Celery app created")
    print(f"  Broker: {app.conf.broker_url}")
    print(f"  Backend: {app.conf.result_backend}")
    
    # Try to connect to Redis
    import redis
    r = redis.Redis(host='localhost', port=6379, db=0)
    r.ping()
    print("✓ Redis connection successful")
    
    # Check queue
    queue_len = r.llen('celery')
    print(f"✓ Redis queue 'celery' length: {queue_len}")
    
    # Try to send a test task (this will fail but shows if queueing works)
    try:
        task = app.send_task('test.task', args=[1, 2])
        print(f"✓ Task queued: {task.id}")
        print(f"  Task state: {task.state}")
        
        # Check queue again
        queue_len_after = r.llen('celery')
        print(f"✓ Redis queue 'celery' length after send: {queue_len_after}")
        
        if queue_len_after > queue_len:
            print("✓ Task successfully added to Redis queue!")
        else:
            print("✗ WARNING: Queue length did not increase")
            
    except Exception as e:
        print(f"✗ Error sending task: {e}")
        
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
PYEOF

echo ""
echo "=================================================================="
echo "Diagnostic complete"
echo "=================================================================="
