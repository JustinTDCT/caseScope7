#!/usr/bin/env python3
"""
caseScope 9.0.0 - Utility Functions
Copyright (c) 2025 Justin Dube <casescope@thedubes.net>

Shared utility functions for caseScope application.
"""

from flask import request
from flask_login import current_user
from opensearchpy import OpenSearch, RequestsHttpConnection
from models import db, AuditLog


def get_opensearch_client():
    """
    Create and return an OpenSearch client with standard configuration.
    
    Returns:
        OpenSearch: Configured OpenSearch client
    """
    return OpenSearch(
        hosts=[{'host': 'localhost', 'port': 9200}],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        connection_class=RequestsHttpConnection,
        timeout=30
    )


def log_audit(action, category, details=None, success=True, username=None):
    """
    Log an audit event to the database.
    
    Args:
        action (str): Action performed (login, upload, delete, etc.)
        category (str): Category of action (authentication, file_operation, etc.)
        details (str, optional): Additional details about the action
        success (bool): Whether the action succeeded
        username (str, optional): Username (defaults to current_user if authenticated)
    """
    try:
        # Get real client IP from X-Forwarded-For header (set by Nginx proxy)
        # Falls back to remote_addr if header not present
        forwarded_for = request.headers.get('X-Forwarded-For', request.remote_addr)
        # X-Forwarded-For can be comma-separated if multiple proxies, take first (real client)
        client_ip = forwarded_for.split(',')[0].strip() if forwarded_for else request.remote_addr
        
        audit = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            username=username or (current_user.username if current_user.is_authenticated else 'Anonymous'),
            action=action,
            category=category,
            details=details,
            ip_address=client_ip,
            success=success
        )
        db.session.add(audit)
        db.session.commit()
    except Exception as e:
        print(f"[Audit Log] Error logging {action}: {e}")
        db.session.rollback()


def format_bytes(bytes_value):
    """
    Format bytes into human-readable string.
    
    Args:
        bytes_value (int): Number of bytes
        
    Returns:
        str: Formatted string (e.g., "1.5 GB", "250 MB")
    """
    if not bytes_value:
        return "0 B"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def sanitize_filename(filename):
    """
    Sanitize a filename to prevent path traversal and other security issues.
    
    Args:
        filename (str): Original filename
        
    Returns:
        str: Sanitized filename
    """
    import re
    import os
    
    # Remove any directory components
    filename = os.path.basename(filename)
    
    # Remove or replace problematic characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250] + ext
    
    return filename


def make_index_name(case_id, filename):
    """
    Generate OpenSearch index name from case ID and filename.
    
    This must match the function in tasks.py to ensure consistency.
    
    Args:
        case_id (int): Case ID
        filename (str): Original filename
        
    Returns:
        str: Index name (e.g., "case_1_security.evtx")
    """
    import re
    
    # Sanitize filename for index name
    # Remove extension, lowercase, replace non-alphanumeric with underscore
    base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
    safe_name = re.sub(r'[^a-z0-9_-]', '_', base_name.lower())
    
    # OpenSearch index names must be lowercase and can't start with underscore
    if safe_name.startswith('_'):
        safe_name = 'file' + safe_name
    
    return f"case_{case_id}_{safe_name}"

