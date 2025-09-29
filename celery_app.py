#!/usr/bin/env python3
"""
caseScope 7.1 - Celery Worker Configuration
Handles background processing for file indexing and SIGMA rule processing
"""

from celery import Celery
import os

# Initialize Celery
celery_app = Celery(
    'casescope',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0'
)

# Celery Configuration
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
)

# Import tasks
celery_app.autodiscover_tasks(['tasks'])

if __name__ == '__main__':
    celery_app.start()
