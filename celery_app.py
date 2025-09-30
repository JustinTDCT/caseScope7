#!/usr/bin/env python3
"""
caseScope 7.1 - Celery Worker Configuration
Handles background processing for file indexing and SIGMA rule processing
"""

from celery import Celery
from celery.signals import (
    worker_ready, worker_shutdown, 
    task_prerun, task_postrun, task_failure, task_received,
    before_task_publish, after_task_publish
)
import os
import sys

# Enable verbose logging
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

logger.info("="*80)
logger.info("CELERY WORKER INITIALIZATION")
logger.info("="*80)

# Initialize Celery
logger.info("Creating Celery app with Redis broker...")
celery_app = Celery(
    'casescope',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0'
)

# Celery Configuration
logger.info("Configuring Celery app...")
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    task_soft_time_limit=3300,  # 55 minute soft limit
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=50,
    # Explicit queue configuration
    task_default_queue='celery',
    task_default_exchange='celery',
    task_default_exchange_type='direct',
    task_default_routing_key='celery',
    # CRITICAL: Transport hardening to guarantee single Redis LIST key
    # Prevents fan-out to celery0..9, ensures web and worker use same key
    broker_transport_options={
        'priority_steps': [0],  # Disable celery0..9 fan-out
        'visibility_timeout': 3600,
    },
    # Prevent Celery from hijacking root logger
    worker_hijack_root_logger=False,
    # Detailed log formats for debugging
    worker_log_format='[%(asctime)s] [%(levelname)s] [%(processName)s/%(name)s] %(message)s',
    worker_task_log_format='[%(asctime)s] [%(levelname)s] [%(task_name)s(%(task_id)s)] %(message)s',
    # Enable task-sent events for better visibility
    task_send_sent_event=True,
)

# Signal handlers for verbose logging
@worker_ready.connect
def on_worker_ready(sender, **kwargs):
    logger.info("="*80)
    logger.info("CELERY WORKER READY - Waiting for tasks...")
    logger.info(f"Worker instance: {sender}")
    logger.info(f"Broker URL: {celery_app.conf.broker_url}")
    logger.info(f"Result backend: {celery_app.conf.result_backend}")
    logger.info(f"Registered tasks: {list(celery_app.tasks.keys())}")
    
    # Check Redis connection
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.ping()
        queue_length = r.llen('celery')
        logger.info(f"Redis connection: OK")
        logger.info(f"Redis queue 'celery' length: {queue_length}")
        
        # List all keys in Redis
        keys = r.keys('*')
        logger.info(f"All Redis keys: {keys}")
    except Exception as e:
        logger.error(f"Redis connection error: {e}")
    
    logger.info("="*80)

@worker_shutdown.connect
def on_worker_shutdown(sender, **kwargs):
    logger.info("="*80)
    logger.info("CELERY WORKER SHUTDOWN")
    logger.info("="*80)

@task_prerun.connect
def on_task_prerun(sender, task_id, task, args, kwargs, **extra):
    logger.info(f"[TASK START] {task.name} (ID: {task_id})")
    logger.debug(f"[TASK START] Args: {args}, Kwargs: {kwargs}")

@task_postrun.connect
def on_task_postrun(sender, task_id, task, args, kwargs, retval, **extra):
    logger.info(f"[TASK COMPLETE] {task.name} (ID: {task_id})")
    logger.debug(f"[TASK COMPLETE] Return value: {retval}")

@task_failure.connect
def on_task_failure(sender, task_id, exception, args, kwargs, traceback, einfo, **extra):
    logger.error(f"[TASK FAILED] {sender.name} (ID: {task_id})")
    logger.error(f"[TASK FAILED] Exception: {exception}")
    logger.error(f"[TASK FAILED] Traceback: {traceback}")

@task_received.connect
def on_task_received(request=None, **kwargs):
    """Log the exact moment a task lands on the worker"""
    logger.info("="*80)
    logger.info(f"[TASK RECEIVED] Task landed on worker!")
    logger.info(f"[TASK RECEIVED] Task ID: {request.id}")
    logger.info(f"[TASK RECEIVED] Task Name: {request.name}")
    logger.info(f"[TASK RECEIVED] Args: {request.argsrepr}")
    logger.info(f"[TASK RECEIVED] Kwargs: {request.kwargsrepr}")
    logger.info(f"[TASK RECEIVED] ETA: {request.eta}")
    logger.info(f"[TASK RECEIVED] Retries: {request.retries}")
    logger.info("="*80)

@before_task_publish.connect
def on_before_publish(headers=None, body=None, exchange=None, routing_key=None, **kwargs):
    """Log when web process is about to publish a task"""
    logger.info(f"[TASK PUBLISH] Preparing to send task: {headers.get('task') if headers else 'unknown'}")
    logger.info(f"[TASK PUBLISH] Routing key: {routing_key}, Exchange: {exchange}")

@after_task_publish.connect
def on_after_publish(headers=None, body=None, exchange=None, routing_key=None, **kwargs):
    """Log when web process successfully published a task"""
    task_id = headers.get('id') if headers else 'unknown'
    task_name = headers.get('task') if headers else 'unknown'
    logger.info(f"[TASK SENT] Successfully queued task to Redis")
    logger.info(f"[TASK SENT] Task ID: {task_id}")
    logger.info(f"[TASK SENT] Task Name: {task_name}")
    logger.info(f"[TASK SENT] Routing key: {routing_key}")

# Import tasks
logger.info("Auto-discovering tasks...")
celery_app.autodiscover_tasks(['tasks'])
logger.info("Celery app initialization complete")

if __name__ == '__main__':
    celery_app.start()
