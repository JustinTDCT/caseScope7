#!/usr/bin/env python3
"""
caseScope 7.1.1 - Main Application Entry Point
Copyright (c) 2025 Justin Dube <casescope@thedubes.net>
"""

import os
import sys
import json
import html
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from datetime import datetime
from opensearchpy import OpenSearch
import re
from sqlalchemy import select, delete
import psutil
import sqlalchemy

# Import dark flat theme CSS
from theme import get_theme_css

# Import the SAME Celery app that the worker uses (no more split-brain!)
# This ensures web and worker use identical configuration and routing
try:
    from celery_app import celery_app
    print("[Main] Imported shared celery_app from celery_app.py")
except ImportError as e:
    celery_app = None  # Celery not available (development mode)
    print(f"[Main] WARNING: Could not import celery_app: {e}")

# Version Management
def get_version():
    try:
        with open('version.json', 'r') as f:
            return json.load(f)['version']
    except:
        return "7.1.1"

APP_VERSION = get_version()

# Flask Application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'casescope-7.1-production-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:////opt/casescope/data/casescope.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Template filters
@app.template_filter('from_json')
def from_json_filter(value):
    """Parse JSON string to Python object"""
    if not value:
        return []
    try:
        return json.loads(value)
    except:
        return []

# OpenSearch Client
opensearch_client = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_compress=True,
    use_ssl=False,
    verify_certs=False,
    timeout=30
)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='read-only')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    force_password_change = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

class CaseTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    description = db.Column(db.Text)
    default_priority = db.Column(db.String(20), default='Medium')
    default_tags = db.Column(db.String(500))
    checklist = db.Column(db.Text)  # JSON array of checklist items
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship
    creator = db.relationship('User', backref='case_templates')
    
    def __repr__(self):
        return f'<CaseTemplate {self.name}>'

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Null for failed logins
    username = db.Column(db.String(80))  # Store username even if user deleted
    action = db.Column(db.String(100), nullable=False)  # login, logout, upload, delete, search, etc.
    category = db.Column(db.String(50), nullable=False)  # authentication, file_operation, search, admin
    details = db.Column(db.Text)  # JSON string with additional details
    ip_address = db.Column(db.String(45))  # IPv4 or IPv6
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    success = db.Column(db.Boolean, default=True)  # For tracking failed operations
    
    # Relationship
    user = db.relationship('User', backref='audit_logs')

class SavedSearch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=True)  # Null = all cases
    name = db.Column(db.String(200), nullable=False)
    query = db.Column(db.Text, nullable=False)
    time_range = db.Column(db.String(50))  # 24h, 7d, 30d, custom, all
    custom_start = db.Column(db.DateTime)  # For custom range
    custom_end = db.Column(db.DateTime)    # For custom range
    violations_only = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    use_count = db.Column(db.Integer, default=0)
    
    # Relationships
    user = db.relationship('User', backref='saved_searches')
    case = db.relationship('Case', backref='saved_searches')

class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    query = db.Column(db.Text, nullable=False)
    time_range = db.Column(db.String(50))
    violations_only = db.Column(db.Boolean, default=False)
    result_count = db.Column(db.Integer)
    executed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='search_history')
    case = db.relationship('Case', backref='search_history')

class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    case_number = db.Column(db.String(50), unique=True, nullable=False)
    priority = db.Column(db.String(20), default='Medium')  # Low, Medium, High, Critical
    status = db.Column(db.String(20), default='Open')     # Open, In Progress, Closed, Archived
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    closed_at = db.Column(db.DateTime)
    closed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    template_id = db.Column(db.Integer, db.ForeignKey('case_template.id'))
    tags = db.Column(db.String(500))  # Comma-separated tags
    company = db.Column(db.String(200))  # Company/Customer name for DFIR-IRIS
    
    # DFIR-IRIS Integration Fields
    iris_company_id = db.Column(db.Integer)  # DFIR-IRIS company ID
    iris_case_id = db.Column(db.Integer)  # DFIR-IRIS case ID
    iris_synced_at = db.Column(db.DateTime)  # Last sync timestamp
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_cases')
    assignee = db.relationship('User', foreign_keys=[assignee_id], backref='assigned_cases')
    closer = db.relationship('User', foreign_keys=[closed_by], backref='closed_cases')
    template = db.relationship('CaseTemplate', backref='cases')
    
    def __repr__(self):
        return f'<Case {self.case_number}: {self.name}>'
    
    @property
    def file_count(self):
        """Get number of files in this case"""
        return db.session.query(CaseFile).filter_by(case_id=self.id, is_deleted=False).count()
    
    @property
    def total_events(self):
        """Get total number of indexed events in this case"""
        # This will be implemented when we add event indexing
        return 0
    
    @property
    def storage_size(self):
        """Get total storage size for this case"""
        files = db.session.query(CaseFile).filter_by(case_id=self.id, is_deleted=False).all()
        return sum(f.file_size for f in files if f.file_size)

class CaseFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.BigInteger)
    file_hash = db.Column(db.String(64))  # SHA256
    mime_type = db.Column(db.String(100))
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    indexed_at = db.Column(db.DateTime)
    is_indexed = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
    event_count = db.Column(db.Integer, default=0)
    estimated_event_count = db.Column(db.Integer, default=0)  # Estimated total events for progress
    violation_count = db.Column(db.Integer, default=0)
    indexing_status = db.Column(db.String(20), default='Queued')  # Queued, Estimating, Indexing, SIGMA Hunting, IOC Hunting, Completed, Failed
    celery_task_id = db.Column(db.String(100), nullable=True)  # Current Celery task ID for progress tracking
    
    # Relationships
    case = db.relationship('Case', backref='files')
    uploader = db.relationship('User', backref='uploaded_files')
    
    def __repr__(self):
        return f'<CaseFile {self.original_filename} in Case {self.case_id}>'

class SigmaRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    title = db.Column(db.String(500))
    description = db.Column(db.Text)
    author = db.Column(db.String(200))
    level = db.Column(db.String(20))  # low, medium, high, critical
    status = db.Column(db.String(20))  # test, experimental, stable
    rule_yaml = db.Column(db.Text, nullable=False)  # Full YAML content
    rule_hash = db.Column(db.String(64), unique=True)  # SHA256 of YAML
    is_enabled = db.Column(db.Boolean, default=True)
    is_builtin = db.Column(db.Boolean, default=False)  # Built-in vs user-uploaded
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(100))  # process_creation, network_connection, etc.
    tags = db.Column(db.Text)  # JSON array of tags
    
    # Relationships
    uploader = db.relationship('User', backref='uploaded_rules')
    
    def __repr__(self):
        return f'<SigmaRule {self.name}>'

class SigmaViolation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('case_file.id'), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey('sigma_rule.id'), nullable=False)
    event_id = db.Column(db.String(100))  # OpenSearch document ID
    event_data = db.Column(db.Text)  # JSON of matched event
    matched_fields = db.Column(db.Text)  # JSON of fields that matched
    severity = db.Column(db.String(20))  # From rule level
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_reviewed = db.Column(db.Boolean, default=False)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    reviewed_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    
    # Relationships
    case = db.relationship('Case', backref='violations')
    file = db.relationship('CaseFile', backref='violations')
    rule = db.relationship('SigmaRule', backref='violations')
    reviewer = db.relationship('User', backref='reviewed_violations')

class EventTag(db.Model):
    """Timeline and analysis tags for events"""
    __tablename__ = 'event_tag'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    event_id = db.Column(db.String(100), nullable=False)  # OpenSearch document ID (hash)
    index_name = db.Column(db.String(200), nullable=False)  # OpenSearch index name
    event_timestamp = db.Column(db.String(100))  # Event's actual timestamp for sorting
    tag_type = db.Column(db.String(50), default='timeline')  # timeline, important, suspicious, etc.
    color = db.Column(db.String(20), default='blue')  # Color coding for timeline visualization
    notes = db.Column(db.Text)  # Analyst notes about why this event is tagged
    tagged_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tagged_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', backref='tagged_events')
    tagger = db.relationship('User', backref='tagged_events')
    
    # Unique constraint: one user can only tag an event once per type
    __table_args__ = (
        db.UniqueConstraint('case_id', 'event_id', 'tagged_by', 'tag_type', name='unique_event_tag'),
    )
    
    def __repr__(self):
        return f'<EventTag Case:{self.case_id} Event:{self.event_id[:8]} By:{self.tagged_by}>'

class IOC(db.Model):
    """Indicators of Compromise for threat hunting"""
    __tablename__ = 'ioc'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    
    # IOC Details
    ioc_type = db.Column(db.String(50), nullable=False)  # ip, domain, fqdn, hostname, username, hash_md5, hash_sha1, hash_sha256, command, filename, process_name, malware_name, registry_key, email, url
    ioc_value = db.Column(db.String(1000), nullable=False)  # The actual indicator value
    ioc_value_normalized = db.Column(db.String(1000))  # Lowercase/normalized for matching
    
    # Context
    description = db.Column(db.Text)  # What this IOC represents
    source = db.Column(db.String(200))  # Where it came from (threat intel, manual analysis, etc.)
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    
    # Status
    is_active = db.Column(db.Boolean, default=True)  # Active for hunting
    
    # Threat Hunting Results
    match_count = db.Column(db.Integer, default=0)  # Number of events matching this IOC
    last_seen = db.Column(db.DateTime)  # Last time this IOC was seen in events
    last_hunted = db.Column(db.DateTime)  # Last time hunting was performed
    
    # Metadata
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)  # Analyst notes
    
    # Relationships
    case = db.relationship('Case', backref='iocs')
    analyst = db.relationship('User', backref='iocs_added')
    
    def __repr__(self):
        return f'<IOC {self.ioc_type}:{self.ioc_value[:30]}>'

class IOCMatch(db.Model):
    """Records of IOC matches found in events"""
    __tablename__ = 'ioc_match'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    ioc_id = db.Column(db.Integer, db.ForeignKey('ioc.id'), nullable=False)
    
    # Event Information
    event_id = db.Column(db.String(100), nullable=False)  # OpenSearch document ID
    index_name = db.Column(db.String(200), nullable=False)
    event_timestamp = db.Column(db.String(100))  # For sorting
    source_filename = db.Column(db.String(300))  # Source EVTX/NDJSON file
    
    # Match Details
    matched_field = db.Column(db.String(200))  # Which field contained the IOC
    matched_value = db.Column(db.Text)  # The actual value that matched
    
    # Metadata
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    hunt_type = db.Column(db.String(20), default='manual')  # manual or automatic
    
    # Relationships
    case = db.relationship('Case', backref='ioc_matches')
    ioc = db.relationship('IOC', backref='matches')
    
    # Unique constraint: one match per IOC per event
    __table_args__ = (
        db.UniqueConstraint('case_id', 'ioc_id', 'event_id', name='unique_ioc_event_match'),
    )
    
    def __repr__(self):
        return f'<IOCMatch IOC:{self.ioc_id} Event:{self.event_id[:8]}>'

class SystemSettings(db.Model):
    """System-wide settings for integrations and configuration"""
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.Text)
    setting_type = db.Column(db.String(20), default='string')  # string, boolean, integer, json
    description = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __repr__(self):
        return f'<SystemSettings {self.setting_key}={self.setting_value[:30]}>'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Audit logging helper
def log_audit(action, category, details=None, success=True, username=None):
    """Log an audit event"""
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

# System Settings Helper Functions
def get_setting(key, default=None):
    """Get a system setting value (SQLAlchemy 2.0)"""
    from sqlalchemy import select
    stmt = select(SystemSettings).where(SystemSettings.setting_key == key)
    setting = db.session.execute(stmt).scalar_one_or_none()
    
    if not setting:
        return default
    
    # Convert based on type
    if setting.setting_type == 'boolean':
        return setting.setting_value.lower() in ['true', '1', 'yes']
    elif setting.setting_type == 'integer':
        try:
            return int(setting.setting_value)
        except:
            return default
    elif setting.setting_type == 'json':
        try:
            import json
            return json.loads(setting.setting_value)
        except:
            return default
    else:
        return setting.setting_value

def set_setting(key, value, setting_type='string', description=None):
    """Set a system setting value (SQLAlchemy 2.0)"""
    from sqlalchemy import select
    
    stmt = select(SystemSettings).where(SystemSettings.setting_key == key)
    setting = db.session.execute(stmt).scalar_one_or_none()
    
    if not setting:
        setting = SystemSettings(setting_key=key)
        db.session.add(setting)
    
    setting.setting_value = str(value)
    setting.setting_type = setting_type
    if description:
        setting.description = description
    if current_user.is_authenticated:
        setting.updated_by = current_user.id
    
    db.session.commit()
    return setting

# ============================================================================
# Search Helper Functions (Refactored from 401-line search() function)
# ============================================================================

def extract_event_fields(source_dict, hit_id):
    """
    Extract standardized fields from an OpenSearch event document.
    
    CRITICAL: Maintains dual-field mapping for compatibility:
    - System.EventID.#text (structured) + System.EventID (text)
    - System.TimeCreated.#attributes.SystemTime (structured) + @timestamp (text)
    
    Args:
        source_dict: OpenSearch _source dictionary
        hit_id: OpenSearch document _id
        
    Returns:
        dict with standardized fields (timestamp, event_id, computer, etc.)
    """
    # Get timestamp from various possible fields (dual-mapping aware)
    # NOTE: evtx_dump uses #attributes for XML attributes, not @ prefix
    timestamp = source_dict.get('System.TimeCreated.#attributes.SystemTime') or \
               source_dict.get('System.TimeCreated.@SystemTime') or \
               source_dict.get('System.TimeCreated.SystemTime') or \
               source_dict.get('System_TimeCreated_SystemTime') or \
               source_dict.get('@timestamp') or \
               'N/A'
    
    # Get Event ID (XML text node notation) - dual-mapping aware
    event_id = source_dict.get('System.EventID.#text') or \
              source_dict.get('System.EventID') or \
              source_dict.get('System_EventID') or \
              source_dict.get('EventID') or \
              'N/A'
    
    # Get source filename from metadata
    metadata = source_dict.get('_casescope_metadata', {})
    source_file = metadata.get('filename', 'Unknown')
    source_type = metadata.get('source_type', 'evtx')
    
    # Get computer name (EVTX or EDR)
    computer = source_dict.get('System.Computer') or \
              source_dict.get('System_Computer') or \
              source_dict.get('Computer') or \
              source_dict.get('host', {}).get('hostname') or \
              source_dict.get('host', {}).get('name') or \
              'N/A'
    
    # Get channel (EVTX only)
    channel = source_dict.get('System.Channel') or \
             source_dict.get('System_Channel') or \
             'N/A'
    
    # Get provider (EVTX XML attribute notation) - dual-mapping aware
    # NOTE: evtx_dump uses #attributes for XML attributes
    provider = source_dict.get('System.Provider.#attributes.Name') or \
              source_dict.get('System.Provider.@Name') or \
              source_dict.get('System.Provider.Name') or \
              source_dict.get('System_Provider_Name') or \
              'N/A'
    
    # Determine event description based on source type
    if source_type == 'ndjson':
        # EDR telemetry - use command_line as Event Type
        process_data = source_dict.get('process', {})
        command_line = process_data.get('command_line', '')
        
        if command_line:
            event_description = command_line
        else:
            # Fallback to process name if no command line
            process_name = process_data.get('name', 'Unknown Process')
            event_description = f"Process: {process_name}"
        
        event_id = 'EDR'  # Tag EDR events
    else:
        # EVTX - use traditional event description
        event_description = get_event_description(event_id, channel, provider, source_dict)
    
    # Get SIGMA violations if present
    sigma_violations = source_dict.get('sigma_detections', [])
    has_violations = source_dict.get('has_violations', False)
    
    return {
        'timestamp': timestamp,
        'event_id': event_id,
        'event_type': event_description,
        'source_file': source_file,
        'computer': computer,
        'channel': channel,
        'provider': provider,
        'sigma_violations': sigma_violations,
        'has_violations': has_violations
    }

def build_threat_filter_query(threat_filter):
    """
    Build OpenSearch filter query for threat filtering.
    
    Args:
        threat_filter: One of 'none', 'sigma', 'ioc', 'either', 'both'
        
    Returns:
        dict: OpenSearch filter query or None
    """
    print(f"[Search] Threat filter selected: {threat_filter}")
    
    if threat_filter == 'sigma':
        query = {"exists": {"field": "has_violations"}}
        print(f"[Search] Added SIGMA filter: {query}")
        return query
    elif threat_filter == 'ioc':
        query = {"exists": {"field": "has_ioc_matches"}}
        print(f"[Search] Added IOC filter: {query}")
        return query
    elif threat_filter == 'either':
        query = {"bool": {"should": [
            {"exists": {"field": "has_violations"}},
            {"exists": {"field": "has_ioc_matches"}}
        ], "minimum_should_match": 1}}
        print(f"[Search] Added SIGMA or IOC filter: {query}")
        return query
    elif threat_filter == 'both':
        query = {"bool": {"must": [
            {"exists": {"field": "has_violations"}},
            {"exists": {"field": "has_ioc_matches"}}
        ]}}
        print(f"[Search] Added SIGMA + IOC filter: {query}")
        return query
    
    return None

def build_time_filter_query(time_range, custom_start=None, custom_end=None):
    """
    Build OpenSearch filter query for time range filtering.
    
    Args:
        time_range: One of 'all', '24h', '7d', '30d', 'custom'
        custom_start: Custom start datetime string (for 'custom' range)
        custom_end: Custom end datetime string (for 'custom' range)
        
    Returns:
        dict: OpenSearch filter query or None
    """
    from datetime import timedelta
    
    if time_range == 'all':
        return None
    
    now = datetime.utcnow()
    start_time = None
    end_time = None
    
    if time_range == '24h':
        start_time = now - timedelta(hours=24)
        end_time = now
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
        end_time = now
    elif time_range == '30d':
        start_time = now - timedelta(days=30)
        end_time = now
    elif time_range == 'custom' and custom_start:
        from datetime import datetime as dt
        # Parse custom datetime strings from HTML datetime-local input
        try:
            if 'T' in custom_start:
                start_time = dt.strptime(custom_start, '%Y-%m-%dT%H:%M') if custom_start else None
                end_time = dt.strptime(custom_end, '%Y-%m-%dT%H:%M') if custom_end else now
            else:
                start_time = dt.fromisoformat(custom_start) if custom_start else None
                end_time = dt.fromisoformat(custom_end) if custom_end else now
        except Exception as e:
            print(f"[Search] Error parsing custom datetime: {e}, start='{custom_start}', end='{custom_end}'")
            return None
    
    if not start_time:
        return None
    
    # Format timestamps for OpenSearch date range query
    start_iso = start_time.strftime('%Y-%m-%dT%H:%M:%S')
    end_iso = end_time.strftime('%Y-%m-%dT%H:%M:%S') if end_time else now.strftime('%Y-%m-%dT%H:%M:%S')
    
    print(f"[Search] Time filter: range={time_range}, start={start_iso}, end={end_iso}")
    
    # Use OR query to support both new (#attributes) and legacy (@) field names
    time_filter = {
        "bool": {
            "should": [
                {
                    "range": {
                        "System.TimeCreated.#attributes.SystemTime.date": {
                            "gte": start_iso,
                            "lte": end_iso,
                            "format": "strict_date_optional_time"
                        }
                    }
                },
                {
                    "range": {
                        "System.TimeCreated.@SystemTime.date": {
                            "gte": start_iso,
                            "lte": end_iso,
                            "format": "strict_date_optional_time"
                        }
                    }
                }
            ],
            "minimum_should_match": 1
        }
    }
    
    return time_filter

def parse_search_request(request_obj, session_obj):
    """
    Parse search request parameters from POST, IOC filter, threat filter, or GET.
    
    Args:
        request_obj: Flask request object
        session_obj: Flask session object
        
    Returns:
        dict with parsed parameters (query_str, page, threat_filter, etc.)
    """
    # Default values
    params = {
        'query_str': '*',
        'page': 1,
        'threat_filter': 'none',
        'time_range': 'all',
        'custom_start': None,
        'custom_end': None,
        'sort_field': 'relevance',
        'sort_order': 'desc'
    }
    
    # Check for IOC filter from URL query string
    ioc_filter = request_obj.args.get('ioc')
    # Check for threat filter from URL query string
    threat_filter_param = request_obj.args.get('threat_filter')
    
    if request_obj.method == 'POST':
        params['query_str'] = request_obj.form.get('query', '*').strip()
        params['page'] = int(request_obj.form.get('page', 1))
        params['threat_filter'] = request_obj.form.get('threat_filter', 'none')
        params['time_range'] = request_obj.form.get('time_range', session_obj.get('search_time_range', 'all'))
        params['custom_start'] = request_obj.form.get('custom_start', session_obj.get('search_custom_start'))
        params['custom_end'] = request_obj.form.get('custom_end', session_obj.get('search_custom_end'))
        params['sort_field'] = request_obj.form.get('sort', 'relevance')
        params['sort_order'] = request_obj.form.get('sort_order', 'desc')
        
        # Save time filter to session for persistence
        session_obj['search_time_range'] = params['time_range']
        if params['custom_start']:
            session_obj['search_custom_start'] = params['custom_start']
        if params['custom_end']:
            session_obj['search_custom_end'] = params['custom_end']
    elif ioc_filter:
        # Coming from IOC link - search for that IOC value
        params['query_str'] = ioc_filter
        params['threat_filter'] = 'none'
        # Restore time filter from session
        params['time_range'] = session_obj.get('search_time_range', 'all')
        params['custom_start'] = session_obj.get('search_custom_start')
        params['custom_end'] = session_obj.get('search_custom_end')
    elif threat_filter_param:
        # Coming from dashboard tile with threat filter
        params['threat_filter'] = threat_filter_param
        # Restore time filter from session
        params['time_range'] = session_obj.get('search_time_range', 'all')
        params['custom_start'] = session_obj.get('search_custom_start')
        params['custom_end'] = session_obj.get('search_custom_end')
    else:
        # GET request - restore time filter from session
        params['time_range'] = session_obj.get('search_time_range', 'all')
        params['custom_start'] = session_obj.get('search_custom_start')
        params['custom_end'] = session_obj.get('search_custom_end')
    
    return params

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/debug/database')
def debug_database():
    """Debug route to check database status"""
    try:
        user_count = db.session.query(User).count()
        case_count = db.session.query(Case).count()
        file_count = db.session.query(CaseFile).count()
        all_users = db.session.query(User).all()
        user_list = [{"id": u.id, "username": u.username, "email": u.email, "role": u.role, "active": u.is_active} for u in all_users]
        
        return f'''
        <h2>Database Debug Information</h2>
        <p><strong>Total Users:</strong> {user_count}</p>
        <p><strong>Total Cases:</strong> {case_count}</p>
        <p><strong>Total Files:</strong> {file_count}</p>
        <p><strong>Database File:</strong> {app.config['SQLALCHEMY_DATABASE_URI']}</p>
        <h3>All Users:</h3>
        <pre>{user_list}</pre>
        <p><a href="/login">Back to Login</a></p>
        '''
    except Exception as e:
        import traceback
        return f'''
        <h2>Database Error</h2>
        <p><strong>Error:</strong> {e}</p>
        <pre>{traceback.format_exc()}</pre>
        <p><a href="/login">Back to Login</a></p>
        '''

@app.route('/case/create', methods=['GET', 'POST'])
@login_required
def create_case():
    """Create a new case"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        company = request.form.get('company', '').strip()
        priority = request.form.get('priority', 'Medium')
        tags = request.form.get('tags', '').strip()
        template_id = request.form.get('template_id')
        assignee_id = request.form.get('assignee_id')
        
        if not name:
            flash('Case name is required.', 'error')
        else:
            # Generate unique case number
            import time
            case_number = f"CASE-{int(time.time())}"
            
            try:
                new_case = Case(
                    name=name,
                    description=description,
                    company=company if company else None,
                    case_number=case_number,
                    priority=priority,
                    tags=tags,
                    created_by=current_user.id,
                    assignee_id=int(assignee_id) if assignee_id and assignee_id != '' else None
                )
                db.session.add(new_case)
                db.session.commit()
                
                # Create case directory
                import os
                case_dir = f"/opt/casescope/uploads/{new_case.id}"
                os.makedirs(case_dir, exist_ok=True)
                
                # Set active case in session
                session['active_case_id'] = new_case.id
                
                # Log the action
                log_audit('create_case', 'case_management', f'Created case: {name} (ID: {new_case.id})', success=True)
                
                flash(f'Case "{name}" created successfully!', 'success')
                return redirect(url_for('case_dashboard'))
                
            except Exception as e:
                db.session.rollback()
                flash(f'Error creating case: {str(e)}', 'error')
    
    # GET request - load users for the form
    users = db.session.query(User).filter_by(is_active=True).order_by(User.username).all()
    return render_case_form(users)

@app.route('/case/select')
@login_required
def case_selection():
    """Case selection page"""
    cases = db.session.query(Case).filter_by(is_active=True).order_by(Case.updated_at.desc()).all()
    active_case_id = session.get('active_case_id')
    
    return render_case_selection(cases, active_case_id)

@app.route('/case/set/<int:case_id>')
@login_required
def set_active_case(case_id):
    """Set the active case"""
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found.', 'error')
        return redirect(url_for('case_selection'))
    session['active_case_id'] = case_id
    flash(f'Active case set to: {case.name}', 'success')
    return redirect(url_for('case_dashboard'))

@app.route('/case/edit/<int:case_id>', methods=['GET', 'POST'])
@login_required
def edit_case(case_id):
    """Edit case details"""
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found.', 'error')
        return redirect(url_for('case_selection'))
    
    if request.method == 'POST':
        try:
            # Update case details
            case.name = request.form.get('name', '').strip()
            case.description = request.form.get('description', '').strip()
            case.company = request.form.get('company', '').strip() or None
            case.priority = request.form.get('priority', 'Medium')
            case.status = request.form.get('status', 'Open')
            case.tags = request.form.get('tags', '').strip()
            
            # Handle assignee
            assignee_id = request.form.get('assignee_id')
            if assignee_id and assignee_id != '':
                case.assignee_id = int(assignee_id)
            else:
                case.assignee_id = None
            
            # Validate required fields
            if not case.name:
                flash('Case name is required.', 'error')
                return redirect(url_for('edit_case', case_id=case_id))
            
            case.updated_at = datetime.utcnow()
            db.session.commit()
            
            # Log the action
            log_audit(
                action='edit_case',
                category='case_management',
                details=f'Edited case: {case.name} (ID: {case.id})',
                success=True
            )
            
            flash(f'Case "{case.name}" updated successfully.', 'success')
            
            # Redirect to dashboard if this is the active case
            if session.get('active_case_id') == case_id:
                return redirect(url_for('case_dashboard'))
            else:
                return redirect(url_for('case_selection'))
                
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating case: {str(e)}', 'error')
            return redirect(url_for('edit_case', case_id=case_id))
    
    # GET request - show edit form
    users = db.session.query(User).filter_by(is_active=True).order_by(User.username).all()
    return render_edit_case(case, users)

@app.route('/case/archive/<int:case_id>', methods=['POST'])
@login_required
def archive_case(case_id):
    """Archive a case"""
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'message': 'Case not found'}), 404
    
    try:
        case.status = 'Archived'
        case.is_active = False
        case.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Log the action
        log_audit(
            action='archive_case',
            category='case_management',
            details=f'Archived case: {case.name} (ID: {case.id})',
            success=True
        )
        
        # Clear active case if this was it
        if session.get('active_case_id') == case_id:
            session.pop('active_case_id', None)
        
        return jsonify({'success': True, 'message': f'Case "{case.name}" archived successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/case/close/<int:case_id>', methods=['POST'])
@login_required
def close_case(case_id):
    """Close a case"""
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'message': 'Case not found'}), 404
    
    try:
        case.status = 'Closed'
        case.closed_at = datetime.utcnow()
        case.closed_by = session.get('user_id')
        case.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Log the action
        log_audit(
            action='close_case',
            category='case_management',
            details=f'Closed case: {case.name} (ID: {case.id})',
            success=True
        )
        
        return jsonify({'success': True, 'message': f'Case "{case.name}" closed successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/case/reopen/<int:case_id>', methods=['POST'])
@login_required
def reopen_case(case_id):
    """Reopen a closed/archived case"""
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'message': 'Case not found'}), 404
    
    try:
        case.status = 'In Progress'
        case.is_active = True
        case.closed_at = None
        case.closed_by = None
        case.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Log the action
        log_audit(
            action='reopen_case',
            category='case_management',
            details=f'Reopened case: {case.name} (ID: {case.id})',
            success=True
        )
        
        return jsonify({'success': True, 'message': f'Case "{case.name}" reopened successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/case/delete/<int:case_id>', methods=['POST'])
@login_required
def delete_case(case_id):
    """Permanently delete a case and all associated data"""
    # Admin-only function
    if current_user.role != 'administrator':
        return jsonify({'success': False, 'message': 'Access denied. Administrator role required.'}), 403
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'message': 'Case not found'}), 404
    
    try:
        case_name = case.name
        
        # 1. Delete OpenSearch indices for all case files
        from tasks import make_index_name
        case_files = db.session.query(CaseFile).filter_by(case_id=case_id, is_deleted=False).all()
        
        for file in case_files:
            if file.is_indexed:
                index_name = make_index_name(case_id, file.original_filename)
                try:
                    if opensearch_client.indices.exists(index=index_name):
                        opensearch_client.indices.delete(index=index_name)
                        print(f"[Delete Case] Deleted OpenSearch index: {index_name}")
                except Exception as e:
                    print(f"[Delete Case] Error deleting index {index_name}: {e}")
        
        # 2. Delete files from disk
        import os
        import shutil
        upload_folder = app.config.get('UPLOAD_FOLDER', '/opt/casescope/uploads')
        case_folder = os.path.join(upload_folder, f'case_{case_id}')
        
        if os.path.exists(case_folder):
            try:
                shutil.rmtree(case_folder)
                print(f"[Delete Case] Deleted case folder: {case_folder}")
            except Exception as e:
                print(f"[Delete Case] Error deleting case folder: {e}")
        
        # 3. Delete all associated database records
        # Note: Some will cascade automatically based on foreign key relationships
        
        # Delete IOC matches
        db.session.query(IOCMatch).filter_by(case_id=case_id).delete()
        
        # Delete IOCs
        db.session.query(IOC).filter_by(case_id=case_id).delete()
        
        # Delete event tags
        db.session.execute(
            delete(EventTag).where(EventTag.case_id == case_id)
        )
        
        # Delete SIGMA violations
        db.session.query(SigmaViolation).filter_by(case_id=case_id).delete()
        
        # Delete search history
        db.session.query(SearchHistory).filter_by(case_id=case_id).delete()
        
        # Delete saved searches
        db.session.query(SavedSearch).filter_by(case_id=case_id).delete()
        
        # Delete case files (should cascade, but being explicit)
        db.session.query(CaseFile).filter_by(case_id=case_id).delete()
        
        # Delete the case itself
        db.session.delete(case)
        
        # Commit all deletions
        db.session.commit()
        
        # Clear active case from session if it was this one
        if session.get('active_case_id') == case_id:
            session.pop('active_case_id', None)
        
        # Log the action
        log_audit(
            action='delete_case',
            category='case_management',
            details=f'Permanently deleted case: {case_name} (ID: {case_id}) and all associated data',
            success=True
        )
        
        return jsonify({'success': True, 'message': f'Case "{case_name}" and all associated data deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        print(f"[Delete Case] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error deleting case: {str(e)}'}), 500

@app.route('/case/dashboard')
@login_required
def case_dashboard():
    """Case-specific dashboard"""
    clear_search_filters()  # Clear search filters when leaving search page
    active_case_id = session.get('active_case_id')
    if not active_case_id:
        flash('Please select a case first.', 'warning')
        return redirect(url_for('case_selection'))
    
    case = db.session.get(Case, active_case_id)
    if not case:
        flash('Case not found.', 'error')
        return redirect(url_for('case_selection'))
    
    # Get case-specific statistics
    total_files = db.session.query(CaseFile).filter_by(case_id=case.id, is_deleted=False).count()
    indexed_files = db.session.query(CaseFile).filter_by(case_id=case.id, is_deleted=False, is_indexed=True).count()
    processing_files = db.session.query(CaseFile).filter_by(case_id=case.id, is_deleted=False).filter(
        CaseFile.indexing_status.in_(['Queued', 'Estimating', 'Indexing', 'SIGMA Hunting', 'IOC Hunting'])
    ).count()
    total_events = db.session.query(db.func.sum(CaseFile.event_count)).filter_by(case_id=case.id, is_deleted=False).scalar() or 0
    total_violations = db.session.query(db.func.sum(CaseFile.violation_count)).filter_by(case_id=case.id, is_deleted=False).scalar() or 0
    total_storage = db.session.query(db.func.sum(CaseFile.file_size)).filter_by(case_id=case.id, is_deleted=False).scalar() or 0
    
    # SIGMA rules statistics
    total_sigma_rules = db.session.query(SigmaRule).count()
    enabled_sigma_rules = db.session.query(SigmaRule).filter_by(is_enabled=True).count()
    
    # IOC statistics for this case
    total_iocs = db.session.query(IOC).filter_by(case_id=case.id).count()
    total_ioc_matches = db.session.query(IOCMatch).filter_by(case_id=case.id).count()
    
    return render_case_dashboard(case, total_files, indexed_files, processing_files, total_events, total_violations, total_storage, 
                                 total_sigma_rules, enabled_sigma_rules, total_iocs, total_ioc_matches)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_files():
    """File upload for active case"""
    clear_search_filters()  # Clear search filters when leaving search page
    import hashlib
    import mimetypes
    
    # Require active case
    active_case_id = session.get('active_case_id')
    if not active_case_id:
        flash('Please select a case before uploading files.', 'warning')
        return redirect(url_for('case_selection'))
    
    case = db.session.get(Case, active_case_id)
    if not case:
        flash('Case not found.', 'error')
        return redirect(url_for('case_selection'))
    
    if request.method == 'POST':
        files = request.files.getlist('files')
        
        if not files or files[0].filename == '':
            flash('No files selected.', 'error')
            return redirect(request.url)
        
        # Validate file count
        if len(files) > 5:
            flash('Maximum 5 files allowed per upload.', 'error')
            return redirect(request.url)
        
        success_count = 0
        error_count = 0
        
        for file in files:
            if file.filename == '':
                continue
            
            try:
                # Read file data
                file_data = file.read()
                file_size = len(file_data)
                
                # Validate file size (3GB = 3,221,225,472 bytes)
                if file_size > 3221225472:
                    flash(f'File {file.filename} exceeds 3GB limit.', 'error')
                    error_count += 1
                    continue
                
                # Calculate SHA256 hash
                sha256_hash = hashlib.sha256(file_data).hexdigest()
                
                # Check for duplicate hash in this case
                duplicate = db.session.query(CaseFile).filter_by(
                    case_id=case.id, 
                    file_hash=sha256_hash,
                    is_deleted=False
                ).first()
                
                if duplicate:
                    flash(f'⚠️ File "{file.filename}" already exists in this case (duplicate detected by SHA256 hash). Original file: "{duplicate.original_filename}"', 'warning')
                    error_count += 1
                    continue
                
                # Determine MIME type
                mime_type = mimetypes.guess_type(file.filename)[0] or 'application/octet-stream'
                
                # Generate safe filename
                import time
                timestamp = int(time.time())
                safe_filename = f"{timestamp}_{file.filename}"
                
                # Ensure case upload directory exists
                case_upload_dir = f"/opt/casescope/uploads/{case.id}"
                os.makedirs(case_upload_dir, exist_ok=True)
                
                # Save file
                file_path = os.path.join(case_upload_dir, safe_filename)
                with open(file_path, 'wb') as f:
                    f.write(file_data)
                
                # Create database record with Queued status
                case_file = CaseFile(
                    case_id=case.id,
                    filename=safe_filename,
                    original_filename=file.filename,
                    file_path=file_path,
                    file_size=file_size,
                    file_hash=sha256_hash,
                    mime_type=mime_type,
                    uploaded_by=current_user.id,
                    indexing_status='Queued'  # Changed from 'Uploaded' to show queue status
                )
                
                db.session.add(case_file)
                success_count += 1
                
            except Exception as e:
                flash(f'Error uploading {file.filename}: {str(e)}', 'error')
                error_count += 1
                continue
        
        # Commit all successful uploads
        if success_count > 0:
            try:
                db.session.commit()
                log_audit('file_upload', 'file_operation', f'Uploaded {success_count} file(s) to case {case.name}')
                
                # Trigger complete file processing (queued with 2 concurrent limit)
                try:
                    # Get the files we just uploaded
                    recent_files = db.session.query(CaseFile).filter_by(
                        case_id=case.id,
                        indexing_status='Queued'
                    ).order_by(CaseFile.uploaded_at.desc()).limit(success_count).all()
                    
                    for uploaded_file in recent_files:
                        if celery_app:
                            # Use new queued processing task (index + SIGMA + IOC)
                            celery_app.send_task(
                                'tasks.process_file_complete',
                                args=[uploaded_file.id],
                                queue='celery',
                                priority=0,
                            )
                            print(f"[Upload] Queued complete processing for file ID {uploaded_file.id}: {uploaded_file.original_filename}")
                        else:
                            print(f"[Upload] WARNING: Celery not available, task not queued for file ID {uploaded_file.id}")
                    
                    flash(f'Successfully uploaded {success_count} file(s). Processing queued (max 2 concurrent).', 'success')
                except Exception as e:
                    print(f"[Upload] Warning: Failed to queue processing tasks: {e}")
                    flash(f'Successfully uploaded {success_count} file(s). Manual processing may be required.', 'warning')
                
            except Exception as e:
                db.session.rollback()
                flash(f'Database error: {str(e)}', 'error')
        
        if error_count > 0 and success_count == 0:
            flash(f'{error_count} file(s) failed to upload. Check messages above for details.', 'error')
        elif error_count > 0:
            flash(f'{error_count} file(s) failed to upload. Check messages above for details.', 'warning')
        
        return redirect(url_for('list_files'))
    
    # GET request - show upload form
    return render_upload_form(case)

@app.route('/api/case/stats/<int:case_id>')
@login_required
def get_case_stats(case_id):
    """API endpoint for real-time case statistics (updates every 5s)"""
    # Verify access
    active_case_id = session.get('active_case_id')
    if not active_case_id or int(case_id) != active_case_id:
        return jsonify({'error': 'Access denied'}), 403
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    
    # Get file counts by status
    from sqlalchemy import func
    
    status_counts = db.session.query(
        CaseFile.indexing_status,
        func.count(CaseFile.id)
    ).filter_by(
        case_id=case_id,
        is_deleted=False
    ).group_by(CaseFile.indexing_status).all()
    
    # Convert to dict
    status_dict = {status: count for status, count in status_counts}
    
    # Calculate totals
    total_files = sum(status_dict.values())
    total_events = db.session.query(func.sum(CaseFile.event_count)).filter_by(
        case_id=case_id, is_deleted=False
    ).scalar() or 0
    total_violations = db.session.query(func.sum(CaseFile.violation_count)).filter_by(
        case_id=case_id, is_deleted=False
    ).scalar() or 0
    
    # Count events with IOC matches
    events_with_iocs = db.session.query(
        func.count(func.distinct(IOCMatch.event_id))
    ).filter_by(case_id=case_id).scalar() or 0
    
    return jsonify({
        'status_counts': {
            'queued': status_dict.get('Queued', 0),
            'estimating': status_dict.get('Estimating', 0),
            'indexing': status_dict.get('Indexing', 0),
            'sigma_hunting': status_dict.get('SIGMA Hunting', 0),
            'ioc_hunting': status_dict.get('IOC Hunting', 0),
            'completed': status_dict.get('Completed', 0),
            'failed': status_dict.get('Failed', 0)
        },
        'totals': {
            'total_files': total_files,
            'total_events': total_events,
            'total_violations': total_violations,
            'events_with_iocs': events_with_iocs
        }
    })

@app.route('/files')
@login_required
def list_files():
    """List files in active case"""
    clear_search_filters()  # Clear search filters when leaving search page
    active_case_id = session.get('active_case_id')
    if not active_case_id:
        flash('Please select a case first.', 'warning')
        return redirect(url_for('case_selection'))
    
    case = db.session.get(Case, active_case_id)
    if not case:
        flash('Case not found.', 'error')
        return redirect(url_for('case_selection'))
    files = db.session.query(CaseFile).filter_by(case_id=case.id, is_deleted=False).order_by(CaseFile.uploaded_at.desc()).all()
    
    return render_file_list(case, files)


@app.route('/file-management')
@login_required
def file_management():
    """File management page - view and manage all files across all cases"""
    # Get all files across all cases
    files = db.session.query(CaseFile).filter_by(is_deleted=False).order_by(CaseFile.uploaded_at.desc()).all()
    
    # Get all cases for case filter dropdown
    cases = db.session.query(Case).order_by(Case.name).all()
    
    # Audit log
    log_audit('file_management', 'view', 'Viewed file management page', True)
    
    return render_file_management(files, cases)


@app.route('/file/reindex/<int:file_id>', methods=['POST'])
@login_required
def reindex_file(file_id):
    """Re-index a file: Clear all existing data and re-process from scratch"""
    case_file = db.session.get(CaseFile, file_id) or abort(404)
    
    # Verify file belongs to active case
    active_case_id = session.get('active_case_id')
    if not active_case_id or case_file.case_id != active_case_id:
        flash('Access denied.', 'error')
        return redirect(url_for('list_files'))
    
    try:
        print(f"[Re-index] Starting comprehensive cleanup for file ID {file_id}: {case_file.original_filename}")
        
        # STEP 1: Delete OpenSearch index
        try:
            from opensearchpy import OpenSearch, RequestsHttpConnection
            from tasks import make_index_name
            
            # Use same OpenSearch config as tasks.py
            es = OpenSearch(
                hosts=[{'host': 'localhost', 'port': 9200}],
                http_compress=True,
                use_ssl=False,
                verify_certs=False,
                ssl_assert_hostname=False,
                ssl_show_warn=False,
                connection_class=RequestsHttpConnection,
                timeout=30
            )
            
            index_name = make_index_name(case_file.case_id, case_file.original_filename)
            
            if es.indices.exists(index=index_name):
                es.indices.delete(index=index_name)
                print(f"[Re-index] Deleted OpenSearch index: {index_name}")
            else:
                print(f"[Re-index] OpenSearch index does not exist (skipped): {index_name}")
                
        except Exception as es_error:
            print(f"[Re-index] Error deleting OpenSearch index: {es_error}")
            # Continue anyway - don't fail the re-index
        
        # STEP 2: Delete all SIGMA violations for this file
        violations_deleted = db.session.query(SigmaViolation).filter_by(file_id=file_id).delete()
        if violations_deleted > 0:
            print(f"[Re-index] Deleted {violations_deleted} SIGMA violations")
        
        # STEP 3: Delete all IOC matches for this file
        ioc_matches_deleted = db.session.query(IOCMatch).filter_by(source_filename=case_file.original_filename, case_id=case_file.case_id).delete()
        if ioc_matches_deleted > 0:
            print(f"[Re-index] Deleted {ioc_matches_deleted} IOC matches")
        
        # STEP 4: Delete all timeline tags for events from this file
        # Note: EventTag doesn't have file_id, so we can't directly delete by file
        # These will be orphaned but that's acceptable - they reference non-existent events
        print(f"[Re-index] Note: Timeline tags for deleted events will be orphaned (no file_id reference)")
        
        # STEP 5: Reset file status for fresh processing
        case_file.indexing_status = 'Queued'
        case_file.is_indexed = False
        case_file.indexed_at = None
        case_file.event_count = 0
        case_file.estimated_event_count = 0
        case_file.violation_count = 0
        case_file.celery_task_id = None
        db.session.commit()
        
        print(f"[Re-index] Reset file status to 'Queued', all counters cleared")
        
        # STEP 6: Queue v8.0 sequential processing task
        try:
            if celery_app:
                celery_app.send_task(
                    'tasks.process_file_complete',
                    args=[file_id, 'reindex'],
                    queue='celery',
                    priority=0,
                )
                flash(f'✓ Re-indexing started for {case_file.original_filename}', 'success')
                print(f"[Re-index] Queued v8.0 sequential processing (reindex) for file ID {file_id}")
            else:
                flash(f'Celery worker not available', 'error')
                print(f"[Re-index] ERROR: Celery not available")
        except Exception as e:
            print(f"[Re-index] Error queuing task: {e}")
            flash(f'Re-index queued but worker may not be running. Check logs.', 'warning')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error re-indexing file: {str(e)}', 'error')
        print(f"[Re-index] Database error: {e}")
        import traceback
        traceback.print_exc()
    
    return redirect(url_for('list_files'))


@app.route('/file/rerun-rules/<int:file_id>', methods=['POST'])
@login_required
def rerun_rules(file_id):
    """
    Re-run SIGMA rules on a file
    
    Workflow: Queued → SIGMA Hunting → Completed
    - Keeps event data intact
    - Clears existing SIGMA violations
    - Re-processes with Chainsaw SIGMA engine
    """
    case_file = db.session.get(CaseFile, file_id) or abort(404)
    
    # Verify file belongs to active case
    active_case_id = session.get('active_case_id')
    if not active_case_id or case_file.case_id != active_case_id:
        flash('Access denied.', 'error')
        return redirect(url_for('list_files'))
    
    # Verify file is indexed
    if not case_file.is_indexed:
        flash('File must be indexed before running rules.', 'warning')
        return redirect(url_for('list_files'))
    
    try:
        print(f"[Re-run Rules] Starting SIGMA re-processing for file ID {file_id}: {case_file.original_filename}")
        
        # STEP 1: Delete existing SIGMA violations
        violations_deleted = db.session.query(SigmaViolation).filter_by(file_id=file_id).delete()
        if violations_deleted > 0:
            print(f"[Re-run Rules] Deleted {violations_deleted} existing SIGMA violations")
        
        # STEP 2: Clear has_violations flag in OpenSearch (event data remains)
        try:
            from opensearchpy import OpenSearch, RequestsHttpConnection
            from opensearchpy.helpers import bulk as opensearch_bulk
            from tasks import make_index_name
            
            # Use same OpenSearch config as tasks.py
            es = OpenSearch(
                hosts=[{'host': 'localhost', 'port': 9200}],
                http_compress=True,
                use_ssl=False,
                verify_certs=False,
                ssl_assert_hostname=False,
                ssl_show_warn=False,
                connection_class=RequestsHttpConnection,
                timeout=30
            )
            
            index_name = make_index_name(case_file.case_id, case_file.original_filename)
            
            if es.indices.exists(index=index_name):
                # Bulk update all events to clear SIGMA-related fields
                update_actions = []
                
                # Query all document IDs
                scroll_query = {"query": {"match_all": {}}, "_source": False}
                scroll = es.search(index=index_name, body=scroll_query, scroll='2m', size=1000)
                scroll_id = scroll['_scroll_id']
                hits = scroll['hits']['hits']
                
                while hits:
                    for hit in hits:
                        update_actions.append({
                            '_op_type': 'update',
                            '_index': index_name,
                            '_id': hit['_id'],
                            'doc': {
                                'has_violations': False,
                                'violation_count': 0,
                                'sigma_detections': []
                            }
                        })
                    
                    # Get next batch
                    scroll = es.scroll(scroll_id=scroll_id, scroll='2m')
                    hits = scroll['hits']['hits']
                
                # Clear scroll
                es.clear_scroll(scroll_id=scroll_id)
                
                # Bulk update
                if update_actions:
                    success, failed = opensearch_bulk(es, update_actions, raise_on_error=False)
                    print(f"[Re-run Rules] Cleared SIGMA flags for {success} events in OpenSearch")
                    
        except Exception as es_error:
            print(f"[Re-run Rules] Error clearing OpenSearch SIGMA flags: {es_error}")
            # Continue anyway - SIGMA will re-enrich
        
        # STEP 3: Reset file status to Queued
        case_file.violation_count = 0
        case_file.indexing_status = 'Queued'
        case_file.celery_task_id = None
        db.session.commit()
        print(f"[Re-run Rules] Reset status to 'Queued' for SIGMA re-processing")
        
        # STEP 4: Queue v8.0 sequential processing (SIGMA + IOC)
        try:
            if celery_app:
                task = celery_app.send_task(
                    'tasks.process_file_complete',
                    args=[file_id, 'sigma_only'],
                    queue='celery',
                    priority=0,
                )
                
                # Save task ID for progress tracking
                case_file.celery_task_id = task.id
                db.session.commit()
                
                flash(f'✓ Re-running SIGMA rules for {case_file.original_filename}', 'success')
                print(f"[Re-run Rules] Queued v8.0 sequential processing (sigma_only) task {task.id} for file ID {file_id}")
            else:
                flash(f'Celery worker not available', 'error')
                print(f"[Re-run Rules] ERROR: Celery not available")
        except Exception as e:
            print(f"[Re-run Rules] Error queuing task: {e}")
            import traceback
            traceback.print_exc()
            flash(f'Rule processing queued but worker may not be running. Check logs.', 'warning')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error re-running rules: {str(e)}', 'error')
        print(f"[Re-run Rules] Database error: {e}")
        import traceback
        traceback.print_exc()
    
    return redirect(url_for('list_files'))


@app.route('/file/rehunt-iocs/<int:file_id>', methods=['POST'])
@login_required
def rehunt_iocs(file_id):
    """
    Re-hunt IOCs on a file
    
    Workflow: Queued → IOC Hunting → Completed
    - Keeps event data and SIGMA violations intact
    - Clears existing IOC matches
    - Re-processes with IOC hunting engine
    """
    case_file = db.session.get(CaseFile, file_id) or abort(404)
    
    # Verify file belongs to active case
    active_case_id = session.get('active_case_id')
    if not active_case_id or case_file.case_id != active_case_id:
        flash('Access denied.', 'error')
        return redirect(url_for('list_files'))
    
    # Verify file is indexed
    if not case_file.is_indexed:
        flash('File must be indexed before hunting IOCs.', 'warning')
        return redirect(url_for('list_files'))
    
    try:
        print(f"[Re-hunt IOCs] Starting IOC re-hunting for file ID {file_id}: {case_file.original_filename}")
        
        # STEP 1: Delete existing IOC matches for this file
        ioc_matches_deleted = db.session.query(IOCMatch).filter_by(
            source_filename=case_file.original_filename,
            case_id=case_file.case_id
        ).delete()
        if ioc_matches_deleted > 0:
            print(f"[Re-hunt IOCs] Deleted {ioc_matches_deleted} existing IOC matches")
        
        # STEP 2: Clear has_ioc_matches flag in OpenSearch (event data remains)
        try:
            from opensearchpy import OpenSearch, RequestsHttpConnection
            from opensearchpy.helpers import bulk as opensearch_bulk
            from tasks import make_index_name
            
            # Use same OpenSearch config as tasks.py
            es = OpenSearch(
                hosts=[{'host': 'localhost', 'port': 9200}],
                http_compress=True,
                use_ssl=False,
                verify_certs=False,
                ssl_assert_hostname=False,
                ssl_show_warn=False,
                connection_class=RequestsHttpConnection,
                timeout=30
            )
            
            index_name = make_index_name(case_file.case_id, case_file.original_filename)
            
            if es.indices.exists(index=index_name):
                # Bulk update all events to clear IOC-related fields
                update_actions = []
                
                # Query all document IDs
                scroll_query = {"query": {"match_all": {}}, "_source": False}
                scroll = es.search(index=index_name, body=scroll_query, scroll='2m', size=1000)
                scroll_id = scroll['_scroll_id']
                hits = scroll['hits']['hits']
                
                while hits:
                    for hit in hits:
                        update_actions.append({
                            '_op_type': 'update',
                            '_index': index_name,
                            '_id': hit['_id'],
                            'doc': {
                                'has_ioc_matches': False,
                                'ioc_matches': []
                            }
                        })
                    
                    # Get next batch
                    scroll = es.scroll(scroll_id=scroll_id, scroll='2m')
                    hits = scroll['hits']['hits']
                
                # Clear scroll
                es.clear_scroll(scroll_id=scroll_id)
                
                # Bulk update
                if update_actions:
                    success, failed = opensearch_bulk(es, update_actions, raise_on_error=False)
                    print(f"[Re-hunt IOCs] Cleared IOC flags for {success} events in OpenSearch")
                    
        except Exception as es_error:
            print(f"[Re-hunt IOCs] Error clearing OpenSearch IOC flags: {es_error}")
            # Continue anyway - IOC hunting will re-enrich
        
        # STEP 3: Reset file status to Queued for IOC hunting
        case_file.indexing_status = 'Queued'
        case_file.celery_task_id = None
        db.session.commit()
        print(f"[Re-hunt IOCs] Reset status to 'Queued' for IOC re-hunting")
        
        # STEP 4: Queue v8.0 sequential processing (IOC only)
        try:
            if celery_app:
                task = celery_app.send_task(
                    'tasks.process_file_complete',
                    args=[file_id, 'ioc_only'],
                    queue='celery',
                    priority=0,
                )
                
                # Save task ID for progress tracking
                case_file.celery_task_id = task.id
                db.session.commit()
                
                flash(f'✓ Re-hunting IOCs for {case_file.original_filename}', 'success')
                print(f"[Re-hunt IOCs] Queued v8.0 sequential processing (ioc_only) task {task.id} for file ID {file_id}")
            else:
                flash(f'Celery worker not available', 'error')
                print(f"[Re-hunt IOCs] ERROR: Celery not available")
        except Exception as e:
            print(f"[Re-hunt IOCs] Error queuing task: {e}")
            import traceback
            traceback.print_exc()
            flash(f'IOC hunting queued but worker may not be running. Check logs.', 'warning')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error re-hunting IOCs: {str(e)}', 'error')
        print(f"[Re-hunt IOCs] Database error: {e}")
        import traceback
        traceback.print_exc()
    
    return redirect(url_for('list_files'))


@app.route('/api/reindex-all-files', methods=['POST'])
@login_required
def api_reindex_all_files():
    """API endpoint to re-index all files in a case"""
    try:
        data = request.get_json()
        case_id = data.get('case_id')
        
        if not case_id:
            return jsonify({'success': False, 'message': 'Missing case_id'}), 400
        
        # Verify access
        active_case_id = session.get('active_case_id')
        if not active_case_id or int(case_id) != active_case_id:
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        # Get all indexed files for this case
        files = db.session.query(CaseFile).filter_by(case_id=case_id, is_deleted=False).all()
        
        if not files:
            return jsonify({'success': False, 'message': 'No files found in this case'}), 404
        
        files_queued = 0
        for case_file in files:
            try:
                # Reset file status
                case_file.indexing_status = 'Queued'
                case_file.is_indexed = False
                case_file.indexed_at = None
                case_file.event_count = 0
                case_file.violation_count = 0
                db.session.commit()
                
                # Queue v8.0 sequential processing task
                if celery_app:
                    celery_app.send_task(
                        'tasks.process_file_complete',
                        args=[case_file.id, 'reindex'],
                        queue='celery',
                        priority=0,
                    )
                    files_queued += 1
                    print(f"[Bulk Re-index] Queued v8.0 sequential processing for file ID {case_file.id}: {case_file.original_filename}")
            except Exception as e:
                print(f"[Bulk Re-index] Error queuing file {case_file.id}: {e}")
                continue
        
        return jsonify({
            'success': True,
            'files_queued': files_queued,
            'message': f'Successfully queued {files_queued} file(s) for re-indexing'
        })
    except Exception as e:
        print(f"[Bulk Re-index] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/rerun-all-rules', methods=['POST'])
@login_required
def api_rerun_all_rules():
    """API endpoint to re-run SIGMA rules on all indexed files in a case"""
    try:
        data = request.get_json()
        case_id = data.get('case_id')
        
        if not case_id:
            return jsonify({'success': False, 'message': 'Missing case_id'}), 400
        
        # Verify access
        active_case_id = session.get('active_case_id')
        if not active_case_id or int(case_id) != active_case_id:
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        # Get all indexed files for this case
        files = db.session.query(CaseFile).filter_by(case_id=case_id, is_deleted=False, is_indexed=True).all()
        
        if not files:
            return jsonify({'success': False, 'message': 'No indexed files found in this case'}), 404
        
        files_queued = 0
        for case_file in files:
            try:
                # Delete existing violations for this file
                existing_violations = db.session.query(SigmaViolation).filter_by(file_id=case_file.id).all()
                if existing_violations:
                    print(f"[Bulk Re-run Rules] Deleting {len(existing_violations)} violations for file ID {case_file.id}")
                    for violation in existing_violations:
                        db.session.delete(violation)
                
                # Reset violation status
                case_file.indexing_status = 'Queued'
                case_file.violation_count = 0
                db.session.commit()
                
                # Queue v8.0 sequential processing (SIGMA + IOC)
                if celery_app:
                    celery_app.send_task(
                        'tasks.process_file_complete',
                        args=[case_file.id, 'sigma_only'],
                        queue='celery',
                        priority=0,
                    )
                    files_queued += 1
                    print(f"[Bulk Re-run Rules] Queued v8.0 sequential processing for file ID {case_file.id}: {case_file.original_filename}")
            except Exception as e:
                print(f"[Bulk Re-run Rules] Error queuing file {case_file.id}: {e}")
                continue
        
        return jsonify({
            'success': True,
            'files_queued': files_queued,
            'message': f'Successfully queued {files_queued} file(s) for SIGMA rule processing'
        })
    except Exception as e:
        print(f"[Bulk Re-run Rules] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/rehunt-all-iocs', methods=['POST'])
@login_required
def api_rehunt_all_iocs():
    """
    V8.1 UNIFIED API endpoint to re-hunt IOCs across entire case
    
    New approach:
    - Single task for entire case (not per-file)
    - Bulk clear + hunt all IOCs at once
    - Much faster, consistent results
    """
    try:
        data = request.get_json()
        case_id = data.get('case_id')
        
        if not case_id:
            return jsonify({'success': False, 'message': 'Missing case_id'}), 400
        
        # Verify access
        active_case_id = session.get('active_case_id')
        if not active_case_id or int(case_id) != active_case_id:
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        # Get case
        case = db.session.get(Case, case_id)
        if not case:
            return jsonify({'success': False, 'message': 'Case not found'}), 404
        
        # Check if we have indexed files
        files = db.session.query(CaseFile).filter_by(case_id=case_id, is_deleted=False, is_indexed=True).all()
        if not files:
            return jsonify({'success': False, 'message': 'No indexed files found in this case'}), 404
        
        # Check if we have active IOCs
        active_iocs = db.session.query(IOC).filter_by(case_id=case_id, is_active=True).count()
        if active_iocs == 0:
            return jsonify({'success': False, 'message': 'No active IOCs to hunt. Add IOCs first.'}), 400
        
        print(f"[V8.1 Unified IOC Hunt] Starting for case {case_id} ({case.name})")
        print(f"[V8.1 Unified IOC Hunt] Files: {len(files)}, Active IOCs: {active_iocs}")
        
        # Trigger V8.1 unified IOC hunting task (single task for entire case)
        if celery_app:
            from tasks import hunt_iocs_for_case
            task = hunt_iocs_for_case.delay(case_id)
            
            print(f"[V8.1 Unified IOC Hunt] Queued task {task.id}")
            log_audit('bulk_ioc_rehunt', 'bulk_operations', 
                     f'Started V8.1 unified IOC hunt for {active_iocs} IOCs across {len(files)} files in case {case.name}', 
                     success=True)
            
            return jsonify({
                'success': True,
                'task_id': task.id,
                'files_count': len(files),
                'iocs_count': active_iocs,
                'message': f'Started unified IOC hunt for {active_iocs} IOCs across {len(files)} files'
            })
        else:
            return jsonify({'success': False, 'message': 'Background worker not available. IOC hunting requires Celery.'}), 500
            
    except Exception as e:
        print(f"[V8.1 Unified IOC Hunt] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/update-event-ids', methods=['GET'])
@login_required
def update_event_ids():
    """Update Event ID database (placeholder for future enhancement)"""
    flash('Event ID database is already up to date with 100+ Windows Event IDs. If you download new Event IDs, re-index all files to apply the new descriptions.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/case-management', methods=['GET'])
@login_required
def case_management():
    """Case management page - view and manage all cases"""
    # Get all cases (active and archived)
    cases = db.session.query(Case).order_by(Case.updated_at.desc()).all()
    users = db.session.query(User).filter_by(is_active=True).order_by(User.username).all()
    return render_case_management(cases, users)

@app.route('/templates/create', methods=['POST'])
@login_required
def create_template():
    """Create a new case template"""
    if current_user.role != 'administrator':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        default_priority = request.form.get('default_priority', 'Medium')
        default_tags = request.form.get('default_tags', '').strip()
        checklist = request.form.get('checklist', '').strip()
        
        # Validate
        if not name:
            return jsonify({'success': False, 'message': 'Template name is required'}), 400
        
        # Check for duplicate name
        existing = db.session.query(CaseTemplate).filter_by(name=name).first()
        if existing:
            return jsonify({'success': False, 'message': 'A template with this name already exists'}), 400
        
        # Convert checklist from newline-separated to JSON array
        import json
        if checklist:
            checklist_items = [item.strip() for item in checklist.split('\n') if item.strip()]
            checklist_json = json.dumps(checklist_items)
        else:
            checklist_json = '[]'
        
        new_template = CaseTemplate(
            name=name,
            description=description,
            default_priority=default_priority,
            default_tags=default_tags,
            checklist=checklist_json,
            created_by=current_user.id
        )
        
        db.session.add(new_template)
        db.session.commit()
        
        # Log the action
        log_audit(
            action='create_template',
            category='case_management',
            details=f'Created template: {name}',
            success=True
        )
        
        flash(f'Template "{name}" created successfully.', 'success')
        return jsonify({'success': True, 'message': 'Template created successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/templates/edit/<int:template_id>', methods=['POST'])
@login_required
def edit_template(template_id):
    """Edit a case template"""
    if current_user.role != 'administrator':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    template = db.session.get(CaseTemplate, template_id)
    if not template:
        return jsonify({'success': False, 'message': 'Template not found'}), 404
    
    try:
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        default_priority = request.form.get('default_priority', 'Medium')
        default_tags = request.form.get('default_tags', '').strip()
        checklist = request.form.get('checklist', '').strip()
        is_active = request.form.get('is_active', 'true') == 'true'
        
        # Validate
        if not name:
            return jsonify({'success': False, 'message': 'Template name is required'}), 400
        
        # Check for duplicate name (excluding current template)
        existing = db.session.query(CaseTemplate).filter(
            CaseTemplate.name == name,
            CaseTemplate.id != template_id
        ).first()
        if existing:
            return jsonify({'success': False, 'message': 'A template with this name already exists'}), 400
        
        # Convert checklist from newline-separated to JSON array
        import json
        if checklist:
            checklist_items = [item.strip() for item in checklist.split('\n') if item.strip()]
            checklist_json = json.dumps(checklist_items)
        else:
            checklist_json = '[]'
        
        # Update template
        template.name = name
        template.description = description
        template.default_priority = default_priority
        template.default_tags = default_tags
        template.checklist = checklist_json
        template.is_active = is_active
        
        db.session.commit()
        
        # Log the action
        log_audit(
            action='edit_template',
            category='case_management',
            details=f'Edited template: {name} (ID: {template_id})',
            success=True
        )
        
        flash(f'Template "{name}" updated successfully.', 'success')
        return jsonify({'success': True, 'message': 'Template updated successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/templates/delete/<int:template_id>', methods=['POST'])
@login_required
def delete_template(template_id):
    """Delete a case template"""
    if current_user.role != 'administrator':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    template = db.session.get(CaseTemplate, template_id)
    if not template:
        return jsonify({'success': False, 'message': 'Template not found'}), 404
    
    try:
        # Check if template is in use
        cases_using_template = db.session.query(Case).filter_by(template_id=template_id).count()
        if cases_using_template > 0:
            return jsonify({
                'success': False,
                'message': f'Cannot delete template. It is being used by {cases_using_template} case(s). Consider deactivating instead.'
            }), 400
        
        template_name = template.name
        db.session.delete(template)
        db.session.commit()
        
        # Log the action
        log_audit(
            action='delete_template',
            category='case_management',
            details=f'Deleted template: {template_name} (ID: {template_id})',
            success=True
        )
        
        flash(f'Template "{template_name}" deleted successfully.', 'success')
        return jsonify({'success': True, 'message': 'Template deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/users', methods=['GET'])
@login_required
def user_management():
    """User management page (admin only)"""
    if current_user.role != 'administrator':
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all users
    users = db.session.query(User).order_by(User.created_at.desc()).all()
    
    return render_user_management(users)

@app.route('/users/create', methods=['POST'])
@login_required
def create_user():
    """Create new user (admin only)"""
    if current_user.role != 'administrator':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'read-only')
        
        # Validation
        if not username or not email or not password:
            flash('Username, email, and password are required.', 'error')
            return redirect(url_for('user_management'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return redirect(url_for('user_management'))
        
        if role not in ['administrator', 'analyst', 'read-only']:
            flash('Invalid role specified.', 'error')
            return redirect(url_for('user_management'))
        
        # Check if username or email already exists
        if db.session.query(User).filter_by(username=username).first():
            flash(f'Username "{username}" already exists.', 'error')
            return redirect(url_for('user_management'))
        
        if db.session.query(User).filter_by(email=email).first():
            flash(f'Email "{email}" already exists.', 'error')
            return redirect(url_for('user_management'))
        
        # Create user
        new_user = User(
            username=username,
            email=email,
            role=role,
            is_active=True,
            force_password_change=False
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        log_audit('user_created', 'admin', f'Created user {username} with role {role}')
        flash(f'User "{username}" created successfully.', 'success')
        print(f"[User Management] Created user: {username} (role: {role}) by {current_user.username}")
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating user: {str(e)}', 'error')
        print(f"[User Management] Error creating user: {e}")
    
    return redirect(url_for('user_management'))

@app.route('/users/edit/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    """Edit user (admin only)"""
    if current_user.role != 'administrator':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('user_management'))
    
    try:
        email = request.form.get('email', '').strip()
        role = request.form.get('role', user.role)
        is_active = request.form.get('is_active') == 'true'
        new_password = request.form.get('new_password', '').strip()
        
        # Validation
        if not email:
            flash('Email is required.', 'error')
            return redirect(url_for('user_management'))
        
        if role not in ['administrator', 'analyst', 'read-only']:
            flash('Invalid role specified.', 'error')
            return redirect(url_for('user_management'))
        
        # Check if email already exists (excluding current user)
        existing_user = db.session.query(User).filter_by(email=email).first()
        if existing_user and existing_user.id != user_id:
            flash(f'Email "{email}" already in use.', 'error')
            return redirect(url_for('user_management'))
        
        # Update user
        user.email = email
        user.role = role
        user.is_active = is_active
        
        if new_password:
            if len(new_password) < 8:
                flash('Password must be at least 8 characters.', 'error')
                return redirect(url_for('user_management'))
            user.set_password(new_password)
            user.force_password_change = False
        
        db.session.commit()
        
        log_audit('user_updated', 'admin', f'Updated user {user.username}: role={role}, active={is_active}, password_changed={bool(new_password)}')
        flash(f'User "{user.username}" updated successfully.', 'success')
        print(f"[User Management] Updated user: {user.username} by {current_user.username}")
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating user: {str(e)}', 'error')
        print(f"[User Management] Error updating user: {e}")
    
    return redirect(url_for('user_management'))

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Delete user (admin only)"""
    if current_user.role != 'administrator':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('user_management'))
    
    # Prevent deleting self
    if user.id == current_user.id:
        flash('Cannot delete your own account.', 'error')
        return redirect(url_for('user_management'))
    
    # Prevent deleting last administrator
    if user.role == 'administrator':
        admin_count = db.session.query(User).filter_by(role='administrator').count()
        if admin_count <= 1:
            flash('Cannot delete the last administrator account.', 'error')
            return redirect(url_for('user_management'))
    
    try:
        username = user.username
        user_role = user.role
        db.session.delete(user)
        db.session.commit()
        
        log_audit('user_deleted', 'admin', f'Deleted user {username} (role: {user_role})')
        flash(f'User "{username}" deleted successfully.', 'success')
        print(f"[User Management] Deleted user: {username} by {current_user.username}")
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'error')
        print(f"[User Management] Error deleting user: {e}")
    
    return redirect(url_for('user_management'))

@app.route('/settings', methods=['GET'])
@login_required
def system_settings():
    """System settings page (admin only)"""
    if current_user.role != 'administrator':
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get current settings or defaults (use proper types for defaults)
    settings = {
        'iris_enabled': get_setting('iris_enabled', False),
        'iris_url': get_setting('iris_url', ''),
        'iris_api_key': get_setting('iris_api_key', ''),
        'iris_customer_id': get_setting('iris_customer_id', 1),
        'iris_auto_sync': get_setting('iris_auto_sync', False),
    }
    
    return render_system_settings(settings)

@app.route('/settings/save', methods=['POST'])
@login_required
def save_settings():
    """Save system settings (admin only)"""
    if current_user.role != 'administrator':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        # Get form data
        # For checkboxes: if 'true' appears in the values, checkbox was checked
        iris_enabled_values = request.form.getlist('iris_enabled')
        iris_enabled = 'true' if 'true' in iris_enabled_values else 'false'
        
        iris_url = request.form.get('iris_url', '').strip()
        iris_api_key = request.form.get('iris_api_key', '').strip()
        iris_customer_id = request.form.get('iris_customer_id', '1').strip()
        
        iris_auto_sync_values = request.form.getlist('iris_auto_sync')
        iris_auto_sync = 'true' if 'true' in iris_auto_sync_values else 'false'
        
        # Validate URL if IRIS is enabled
        if iris_enabled == 'true' and iris_url:
            if not iris_url.startswith('http://') and not iris_url.startswith('https://'):
                flash('DFIR-IRIS URL must start with http:// or https://', 'error')
                return redirect(url_for('system_settings'))
        
        # Save settings
        set_setting('iris_enabled', iris_enabled, 'boolean', 'Enable DFIR-IRIS integration')
        set_setting('iris_url', iris_url, 'string', 'DFIR-IRIS server URL')
        set_setting('iris_api_key', iris_api_key, 'string', 'DFIR-IRIS API key')
        set_setting('iris_customer_id', iris_customer_id, 'integer', 'DFIR-IRIS customer ID')
        set_setting('iris_auto_sync', iris_auto_sync, 'boolean', 'Auto-sync to DFIR-IRIS')
        
        log_audit('Settings Updated', 'system', f'Updated DFIR-IRIS integration settings')
        
        flash('Settings saved successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error saving settings: {str(e)}', 'error')
        print(f"[Settings] Error saving: {e}")
    
    return redirect(url_for('system_settings'))

@app.route('/settings/test-iris', methods=['POST'])
@login_required
def test_iris_connection():
    """Test DFIR-IRIS connection (admin only)"""
    if current_user.role != 'administrator':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        import requests
        from urllib3.exceptions import InsecureRequestWarning
        import urllib3
        
        # Suppress SSL warnings for self-signed certificates
        urllib3.disable_warnings(InsecureRequestWarning)
        
        iris_url = request.form.get('iris_url', '').strip()
        iris_api_key = request.form.get('iris_api_key', '').strip()
        
        if not iris_url or not iris_api_key:
            return jsonify({'success': False, 'message': 'Please provide both URL and API Key'})
        
        # Test connection by listing cases (basic read operation)
        # DFIR-IRIS doesn't have a /ping endpoint, so we use /manage/cases/list instead
        test_url = f"{iris_url.rstrip('/')}/manage/cases/list"
        headers = {
            'Authorization': f'Bearer {iris_api_key}',
            'Content-Type': 'application/json'
        }
        
        # Disable SSL verification for self-signed certificates (common in internal deployments)
        response = requests.get(test_url, headers=headers, timeout=10, verify=False)
        
        if response.status_code == 200:
            log_audit('IRIS Connection Test', 'system', 'Connection test successful', success=True)
            return jsonify({
                'success': True,
                'message': '✅ Connected successfully to DFIR-IRIS!',
                'details': f'Server responded with status {response.status_code}'
            })
        else:
            log_audit('IRIS Connection Test', 'system', f'Connection test failed: {response.status_code}', success=False)
            return jsonify({
                'success': False,
                'message': f'❌ Connection failed (HTTP {response.status_code})',
                'details': response.text[:200]
            })
            
    except requests.exceptions.Timeout:
        return jsonify({'success': False, 'message': '❌ Connection timeout - server not responding'})
    except requests.exceptions.ConnectionError:
        return jsonify({'success': False, 'message': '❌ Cannot connect - check URL and network'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'❌ Error: {str(e)}'})

@app.route('/audit-log', methods=['GET'])
@login_required
def audit_log():
    """View audit log (admin only)"""
    if current_user.role != 'administrator':
        flash('Access denied. Administrator privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get filter parameters
    category_filter = request.args.get('category', 'all')
    user_filter = request.args.get('user', 'all')
    success_filter = request.args.get('success', 'all')
    page = int(request.args.get('page', 1))
    per_page = 50
    
    # Build query
    query = AuditLog.query
    
    if category_filter != 'all':
        query = query.filter_by(category=category_filter)
    
    if user_filter != 'all':
        query = query.filter_by(username=user_filter)
    
    if success_filter == 'success':
        query = query.filter_by(success=True)
    elif success_filter == 'failure':
        query = query.filter_by(success=False)
    
    # Get paginated results
    logs_paginated = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get distinct users for filter
    all_users = db.session.query(AuditLog.username).distinct().order_by(AuditLog.username).all()
    all_users = [u[0] for u in all_users if u[0]]
    
    return render_audit_log(logs_paginated, category_filter, user_filter, success_filter, all_users, page, per_page)

@app.route('/violations', methods=['GET'])
@login_required
def violations():
    """View SIGMA rule violations for active case"""
    clear_search_filters()  # Clear search filters when leaving search page
    # Check for active case
    case_id = session.get('active_case_id')
    if not case_id:
        flash('Please select a case first', 'warning')
        return redirect(url_for('case_selection'))
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('case_selection'))
    
    # Get filter parameters
    severity_filter = request.args.get('severity', 'all')
    rule_filter = request.args.get('rule', 'all')
    file_filter = request.args.get('file', 'all')
    reviewed_filter = request.args.get('reviewed', 'all')
    page = int(request.args.get('page', 1))
    per_page = 50
    
    # Build query
    query = db.session.query(SigmaViolation).filter_by(case_id=case_id)
    
    if severity_filter != 'all':
        query = query.filter_by(severity=severity_filter)
    
    if rule_filter != 'all':
        query = query.filter_by(rule_id=int(rule_filter))
    
    if file_filter != 'all':
        query = query.filter_by(file_id=int(file_filter))
    
    if reviewed_filter == 'reviewed':
        query = query.filter_by(is_reviewed=True)
    elif reviewed_filter == 'unreviewed':
        query = query.filter_by(is_reviewed=False)
    
    # Get paginated results
    violations_paginated = query.order_by(SigmaViolation.detected_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get filter options
    all_rules = db.session.query(SigmaRule).join(SigmaViolation).filter(SigmaViolation.case_id == case_id).distinct().all()
    all_files = db.session.query(CaseFile).join(SigmaViolation).filter(SigmaViolation.case_id == case_id).distinct().all()
    
    # Get statistics
    total_violations = db.session.query(SigmaViolation).filter_by(case_id=case_id).count()
    critical_count = db.session.query(SigmaViolation).filter_by(case_id=case_id, severity='critical').count()
    high_count = db.session.query(SigmaViolation).filter_by(case_id=case_id, severity='high').count()
    medium_count = db.session.query(SigmaViolation).filter_by(case_id=case_id, severity='medium').count()
    low_count = db.session.query(SigmaViolation).filter_by(case_id=case_id, severity='low').count()
    reviewed_count = db.session.query(SigmaViolation).filter_by(case_id=case_id, is_reviewed=True).count()
    
    return render_violations_page(
        case, violations_paginated.items, violations_paginated.total,
        page, per_page, severity_filter, rule_filter, file_filter, reviewed_filter,
        all_rules, all_files, total_violations, critical_count, high_count,
        medium_count, low_count, reviewed_count
    )

@app.route('/violation/<int:violation_id>/review', methods=['POST'])
@login_required
def review_violation(violation_id):
    """Mark a violation as reviewed"""
    violation = db.session.get(SigmaViolation, violation_id)
    if not violation:
        return jsonify({'status': 'error', 'message': 'Violation not found'}), 404
    
    notes = request.form.get('notes', '')
    
    violation.is_reviewed = True
    violation.reviewed_by = current_user.id
    violation.reviewed_at = datetime.utcnow()
    violation.notes = notes
    
    db.session.commit()
    
    flash('✓ Violation marked as reviewed', 'success')
    return redirect(url_for('violations'))

# ============================================================================
# IOC MANAGEMENT ROUTES
# ============================================================================

@app.route('/ioc/list', methods=['GET', 'POST'])
@login_required
def ioc_list():
    """IOC Management - View and manage Indicators of Compromise"""
    clear_search_filters()  # Clear search filters when leaving search page
    # Check for active case
    case_id = session.get('active_case_id')
    if not case_id:
        flash('Please select a case first', 'warning')
        return redirect(url_for('case_selection'))
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('case_selection'))
    
    # Handle POST actions (add IOC)
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            ioc_type = request.form.get('ioc_type', '').strip()
            ioc_value = request.form.get('ioc_value', '').strip()
            description = request.form.get('description', '').strip()
            source = request.form.get('source', '').strip()
            severity = request.form.get('severity', 'medium')
            notes = request.form.get('notes', '').strip()
            
            if not ioc_type or not ioc_value:
                flash('IOC type and value are required', 'error')
                return redirect(url_for('ioc_list'))
            
            # Normalize value for matching (lowercase)
            ioc_value_normalized = ioc_value.lower()
            
            # Check for duplicates
            existing = db.session.query(IOC).filter_by(
                case_id=case_id,
                ioc_type=ioc_type,
                ioc_value_normalized=ioc_value_normalized
            ).first()
            
            if existing:
                flash(f'IOC already exists: {existing.ioc_value}', 'warning')
                return redirect(url_for('ioc_list'))
            
            # Create new IOC
            ioc = IOC(
                case_id=case_id,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                ioc_value_normalized=ioc_value_normalized,
                description=description,
                source=source,
                severity=severity,
                notes=notes,
                added_by=current_user.id
            )
            
            db.session.add(ioc)
            db.session.commit()
            
            log_audit('add_ioc', 'ioc_management', f'Added IOC: {ioc_type}={ioc_value}', success=True)
            flash(f'✓ IOC added: {ioc_value}', 'success')
            
            # Auto-sync to DFIR-IRIS if enabled
            try:
                settings = db.session.query(SystemSettings).first()
                if settings and settings.iris_enabled and settings.iris_auto_sync:
                    # Trigger async sync (fire and forget)
                    from iris_sync import sync_case_to_iris
                    import threading
                    sync_thread = threading.Thread(target=sync_case_to_iris, args=(case_id,), daemon=True)
                    sync_thread.start()
                    print(f"[Auto-Sync] IOC added - triggered DFIR-IRIS sync for case {case_id}")
            except Exception as e:
                # Don't fail the IOC add if auto-sync fails
                print(f"[Auto-Sync] Failed to trigger sync after IOC add: {e}")
            
            return redirect(url_for('ioc_list'))
    
    # Get filter parameters
    type_filter = request.args.get('type', 'all')
    severity_filter = request.args.get('severity', 'all')
    status_filter = request.args.get('status', 'active')
    
    # Build query
    query = db.session.query(IOC).filter_by(case_id=case_id)
    
    if type_filter != 'all':
        query = query.filter_by(ioc_type=type_filter)
    
    if severity_filter != 'all':
        query = query.filter_by(severity=severity_filter)
    
    if status_filter == 'active':
        query = query.filter_by(is_active=True)
    elif status_filter == 'inactive':
        query = query.filter_by(is_active=False)
    
    # Get all IOCs
    iocs = query.order_by(IOC.added_at.desc()).all()
    
    # Get statistics
    total_iocs = db.session.query(IOC).filter_by(case_id=case_id).count()
    active_iocs = db.session.query(IOC).filter_by(case_id=case_id, is_active=True).count()
    total_matches = db.session.query(IOCMatch).filter_by(case_id=case_id).count()
    iocs_with_matches = db.session.query(IOC.id).join(IOCMatch).filter(IOC.case_id == case_id).distinct().count()
    
    # Get unique IOC types for filter
    ioc_types = db.session.query(IOC.ioc_type).filter_by(case_id=case_id).distinct().all()
    ioc_types = [t[0] for t in ioc_types]
    
    return render_ioc_management_page(
        case, iocs, total_iocs, active_iocs, total_matches, iocs_with_matches,
        type_filter, severity_filter, status_filter, ioc_types
    )

@app.route('/ioc/edit/<int:ioc_id>', methods=['POST'])
@login_required
def ioc_edit(ioc_id):
    """Edit an IOC"""
    ioc = db.session.get(IOC, ioc_id)
    if not ioc:
        flash('IOC not found', 'error')
        return redirect(url_for('ioc_list'))
    
    # Check case access
    if ioc.case_id != session.get('active_case_id'):
        flash('Access denied', 'error')
        return redirect(url_for('ioc_list'))
    
    # Update fields
    ioc.description = request.form.get('description', '').strip()
    ioc.source = request.form.get('source', '').strip()
    ioc.severity = request.form.get('severity', 'medium')
    ioc.notes = request.form.get('notes', '').strip()
    ioc.is_active = request.form.get('is_active') == 'true'
    
    db.session.commit()
    
    log_audit('edit_ioc', 'ioc_management', f'Edited IOC: {ioc.ioc_type}={ioc.ioc_value}', success=True)
    flash(f'✓ IOC updated: {ioc.ioc_value}', 'success')
    return redirect(url_for('ioc_list'))

@app.route('/ioc/delete/<int:ioc_id>', methods=['POST'])
@login_required
def ioc_delete(ioc_id):
    """Delete an IOC and its matches, with proper OpenSearch and DFIR-IRIS cleanup"""
    ioc = db.session.get(IOC, ioc_id)
    if not ioc:
        flash('IOC not found', 'error')
        return redirect(url_for('ioc_list'))
    
    # Check case access
    if ioc.case_id != session.get('active_case_id'):
        flash('Access denied', 'error')
        return redirect(url_for('ioc_list'))
    
    # Store info for logging
    ioc_info = f'{ioc.ioc_type}={ioc.ioc_value}'
    case_id = ioc.case_id
    
    # Get all events that had this IOC (before deleting matches)
    affected_matches = db.session.query(IOCMatch).filter_by(ioc_id=ioc_id).all()
    affected_events = {}  # {(index_name, event_id): source_filename}
    for match in affected_matches:
        affected_events[(match.index_name, match.event_id)] = match.source_filename
    
    # Delete associated matches
    db.session.query(IOCMatch).filter_by(ioc_id=ioc_id).delete()
    db.session.commit()
    
    # For each affected event, check if it still has IOC matches from OTHER IOCs
    # If not, clear the has_ioc_matches flag in OpenSearch
    if affected_events:
        from opensearchpy import OpenSearch, RequestsHttpConnection
        # Use same OpenSearch config as tasks.py
        es = OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
            connection_class=RequestsHttpConnection,
            timeout=30
        )
        
        events_to_clear = []
        for (index_name, event_id), source_file in affected_events.items():
            # Check if this event has any remaining IOC matches
            remaining_matches = db.session.query(IOCMatch).filter_by(
                case_id=case_id,
                index_name=index_name,
                event_id=event_id
            ).count()
            
            if remaining_matches == 0:
                # No more IOC matches - clear the flag
                events_to_clear.append((index_name, event_id))
        
        # Bulk update OpenSearch to clear has_ioc_matches flag
        if events_to_clear:
            from opensearchpy.helpers import bulk
            actions = []
            for index_name, event_id in events_to_clear:
                actions.append({
                    '_op_type': 'update',
                    '_index': index_name,
                    '_id': event_id,
                    'doc': {
                        'has_ioc_matches': False
                    },
                    'doc_as_upsert': False
                })
            
            try:
                if actions:
                    success, failed = bulk(es, actions, raise_on_error=False)
                    print(f"[IOC Delete] Cleared has_ioc_matches flag for {success} events (after deleting IOC: {ioc_info})")
                    if failed:
                        print(f"[IOC Delete] Failed to clear flags for {len(failed)} events")
            except Exception as e:
                print(f"[IOC Delete] Error clearing has_ioc_matches flags: {e}")
    
    # Delete IOC from database
    db.session.delete(ioc)
    db.session.commit()
    
    # Delete from DFIR-IRIS if sync is enabled
    try:
        settings = db.session.query(SystemSettings).first()
        if settings and settings.iris_enabled:
            from iris_sync import delete_ioc_from_iris
            case = db.session.get(Case, case_id)
            if case:
                # Try to delete from IRIS (fire and forget - don't fail if it errors)
                try:
                    delete_ioc_from_iris(ioc_info, ioc.ioc_type, case_id)
                    print(f"[IOC Delete] Deleted IOC from DFIR-IRIS: {ioc_info}")
                except Exception as iris_error:
                    print(f"[IOC Delete] Failed to delete from DFIR-IRIS (non-fatal): {iris_error}")
    except Exception as e:
        # Don't fail the deletion if IRIS sync fails
        print(f"[IOC Delete] Error during DFIR-IRIS cleanup: {e}")
    
    log_audit('delete_ioc', 'ioc_management', f'Deleted IOC: {ioc_info}', success=True)
    flash(f'✓ IOC deleted: {ioc_info}', 'success')
    return redirect(url_for('ioc_list'))

@app.route('/ioc/hunt', methods=['GET'])
@login_required
def ioc_hunt():
    """Trigger IOC hunting across all indexed events"""
    # Check for active case
    case_id = session.get('active_case_id')
    if not case_id:
        flash('Please select a case first', 'warning')
        return redirect(url_for('case_selection'))
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('case_selection'))
    
    # Get active IOCs
    active_iocs = db.session.query(IOC).filter_by(case_id=case_id, is_active=True).count()
    
    if active_iocs == 0:
        flash('No active IOCs to hunt for. Add IOCs first.', 'warning')
        return redirect(url_for('ioc_list'))
    
    # Trigger V8.1 unified IOC hunting task
    if celery_app:
        from tasks import hunt_iocs_for_case
        task = hunt_iocs_for_case.delay(case_id)
        
        log_audit('ioc_hunt', 'ioc_management', f'Started V8.1 unified IOC hunt for {active_iocs} indicators in case {case.name}', success=True)
        flash(f'🔍 IOC hunt started for {active_iocs} indicators (V8.1 unified hunt). This may take a few minutes...', 'success')
    else:
        flash('Background worker not available. IOC hunting requires Celery.', 'error')
    
    return redirect(url_for('ioc_list'))

@app.route('/iris/sync', methods=['POST'])
@login_required
def iris_sync_case():
    """Sync current case to DFIR-IRIS"""
    # Check for active case
    case_id = session.get('active_case_id')
    if not case_id:
        return jsonify({'success': False, 'message': 'No active case selected'})
    
    case = db.session.get(Case, case_id)
    if not case:
        return jsonify({'success': False, 'message': 'Case not found'})
    
    # Check if IRIS integration is enabled
    iris_enabled = get_setting('iris_enabled', False)
    if not iris_enabled:
        return jsonify({'success': False, 'message': 'DFIR-IRIS integration is not enabled. Configure it in System Settings.'})
    
    # Get IRIS settings
    iris_url = get_setting('iris_url')
    iris_api_key = get_setting('iris_api_key')
    
    if not iris_url or not iris_api_key:
        return jsonify({'success': False, 'message': 'DFIR-IRIS connection not configured. Please configure in System Settings.'})
    
    try:
        # Import sync service
        from iris_sync import IrisSyncService
        
        # Create sync service
        sync_service = IrisSyncService(iris_url, iris_api_key)
        
        # Perform sync
        result = sync_service.sync_case_to_iris(case, db.session)
        
        # Log audit
        if result['success']:
            log_audit(
                'iris_sync',
                'integration',
                f"Synced case '{case.name}' to DFIR-IRIS: {result.get('iocs_synced', 0)} IOCs, {result.get('timeline_synced', 0)} events",
                success=True
            )
        else:
            log_audit(
                'iris_sync_failed',
                'integration',
                f"Failed to sync case '{case.name}' to DFIR-IRIS: {result.get('message', 'Unknown error')}",
                success=False
            )
        
        return jsonify(result)
        
    except Exception as e:
        error_msg = f"Sync failed: {str(e)}"
        logger.error(f"[IRIS Sync] Error: {e}")
        log_audit('iris_sync_failed', 'integration', error_msg, success=False)
        return jsonify({'success': False, 'message': error_msg})

@app.route('/ioc/matches', methods=['GET'])
@login_required
def ioc_matches():
    """View IOC matches for active case"""
    # Check for active case
    case_id = session.get('active_case_id')
    if not case_id:
        flash('Please select a case first', 'warning')
        return redirect(url_for('case_selection'))
    
    case = db.session.get(Case, case_id)
    if not case:
        flash('Case not found', 'error')
        return redirect(url_for('case_selection'))
    
    # Get filter parameters
    ioc_filter = request.args.get('ioc', 'all')
    type_filter = request.args.get('type', 'all')
    hunt_type_filter = request.args.get('hunt_type', 'all')
    page = int(request.args.get('page', 1))
    per_page = 50
    
    # Build query
    query = db.session.query(IOCMatch).filter_by(case_id=case_id)
    
    if ioc_filter != 'all':
        query = query.filter_by(ioc_id=int(ioc_filter))
    
    if type_filter != 'all':
        query = query.join(IOC).filter(IOC.ioc_type == type_filter)
    
    if hunt_type_filter != 'all':
        query = query.filter_by(hunt_type=hunt_type_filter)
    
    # Get paginated results
    matches_paginated = query.order_by(IOCMatch.detected_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get filter options
    all_iocs = db.session.query(IOC).join(IOCMatch).filter(IOCMatch.case_id == case_id).distinct().all()
    
    # Get statistics
    total_matches = db.session.query(IOCMatch).filter_by(case_id=case_id).count()
    manual_count = db.session.query(IOCMatch).filter_by(case_id=case_id, hunt_type='manual').count()
    automatic_count = db.session.query(IOCMatch).filter_by(case_id=case_id, hunt_type='automatic').count()
    unique_iocs = db.session.query(IOCMatch.ioc_id).filter_by(case_id=case_id).distinct().count()
    unique_events = db.session.query(IOCMatch.event_id).filter_by(case_id=case_id).distinct().count()
    
    return render_ioc_matches_page(
        case, matches_paginated.items, matches_paginated.total,
        page, per_page, ioc_filter, type_filter, hunt_type_filter,
        all_iocs, total_matches, manual_count, automatic_count,
        unique_iocs, unique_events
    )

@app.route('/search/export', methods=['POST'])
@login_required
def export_search():
    """Export search results to CSV"""
    import csv
    import io
    from flask import make_response
    
    active_case_id = session.get('active_case_id')
    if not active_case_id:
        flash('Please select a case first.', 'warning')
        return redirect(url_for('case_selection'))
    
    case = db.session.get(Case, active_case_id)
    if not case:
        flash('Case not found.', 'error')
        return redirect(url_for('case_selection'))
    
    query_str = request.form.get('query', '*')
    threat_filter = request.form.get('threat_filter', 'none')
    
    # Get indexed files
    indexed_files = db.session.query(CaseFile).filter_by(case_id=case.id, is_indexed=True, is_deleted=False).all()
    if not indexed_files:
        flash('No indexed files to export.', 'error')
        return redirect(url_for('search'))
    
    from tasks import make_index_name
    indices = [make_index_name(case.id, f.original_filename) for f in indexed_files]
    
    # Build query
    query = build_opensearch_query(query_str)
    filters = []
    
    # Apply threat filtering
    if threat_filter == 'sigma':
        filters.append({"exists": {"field": "has_violations"}})
    elif threat_filter == 'ioc':
        filters.append({"exists": {"field": "has_ioc_matches"}})
    elif threat_filter == 'either':
        filters.append({"bool": {"should": [
            {"exists": {"field": "has_violations"}},
            {"exists": {"field": "has_ioc_matches"}}
        ], "minimum_should_match": 1}})
    elif threat_filter == 'both':
        filters.append({"bool": {"must": [
            {"exists": {"field": "has_violations"}},
            {"exists": {"field": "has_ioc_matches"}}
        ]}})
    
    search_body = {
        "query": {
            "bool": {
                "must": [query],
                "filter": filters
            }
        } if filters else query,
        "_source": True,
        "size": 10000  # Max export size
    }
    
    try:
        response = opensearch_client.search(
            index=','.join(indices),
            body=search_body,
            ignore_unavailable=True
        )
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'Event ID', 'Event Type', 'Computer', 'Source File', 'Has Violations', 'Violation Count', 'Full Event Data'])
        
        for hit in response['hits']['hits']:
            source = hit['_source']
            
            # Extract fields with proper fallbacks
            timestamp = source.get('System_TimeCreated_@SystemTime') or \
                       source.get('System_TimeCreated_SystemTime') or \
                       source.get('System_TimeCreated', {}).get('@SystemTime', '') or \
                       source.get('@timestamp', '')
            
            event_id = source.get('System_EventID_#text') or \
                      source.get('System_EventID', {}).get('#text', '') or \
                      source.get('System_EventID') or \
                      source.get('EventID', '')
            
            event_type = source.get('event_type', 'Unknown Event')
            
            computer = source.get('System_Computer') or \
                      source.get('Computer', '')
            
            # Get source file from metadata
            metadata = source.get('_casescope_metadata', {})
            if isinstance(metadata, dict):
                source_file = metadata.get('filename', '')
            else:
                source_file = ''
            
            has_violations = 'Yes' if source.get('has_violations') else 'No'
            violation_count = source.get('violation_count', 0)
            
            # Full event data as JSON string
            import json
            full_data = json.dumps(source, indent=None)
            
            writer.writerow([timestamp, event_id, event_type, computer, source_file, has_violations, violation_count, full_data])
        
        output.seek(0)
        csv_data = output.getvalue()
        
        log_audit('export_search', 'file_operation', f'Exported {response["hits"]["total"]["value"]} search results from case {case.name}')
        
        resp = make_response(csv_data)
        resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
        resp.headers['Content-Disposition'] = f'attachment; filename="casescope_search_{case.name.replace(" ", "_")}.csv"'
        
        return resp
        
    except Exception as e:
        flash(f'Export error: {str(e)}', 'error')
        return redirect(url_for('search'))

def clear_search_filters():
    """Clear search filter session data when leaving search page"""
    session.pop('search_time_range', None)
    session.pop('search_custom_start', None)
    session.pop('search_custom_end', None)

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    """
    Search indexed events in active case.
    
    REFACTORED: Extracted to helper functions to reduce complexity:
    - parse_search_request(): Parse request parameters
    - build_threat_filter_query(): Build threat filters
    - build_time_filter_query(): Build time range filters
    - extract_event_fields(): Extract fields with dual-mapping support
    """
    # Check if user has active case
    active_case_id = session.get('active_case_id')
    if not active_case_id:
        flash('Please select a case first.', 'warning')
        return redirect(url_for('case_selection'))
    
    case = db.session.get(Case, active_case_id)
    if not case:
        flash('Case not found.', 'error')
        session.pop('active_case_id', None)
        return redirect(url_for('case_selection'))
    
    # Get all indexed files for this case
    indexed_files = db.session.query(CaseFile).filter_by(
        case_id=case.id, is_indexed=True, is_deleted=False
    ).all()
    
    if not indexed_files:
        flash('No indexed files in this case. Upload and index files first.', 'warning')
        return redirect(url_for('list_files'))
    
    # Build list of indices to search
    from tasks import make_index_name
    indices = [make_index_name(case.id, f.original_filename) for f in indexed_files]
    
    # Parse search request parameters (handles POST, IOC filter, threat filter, GET)
    params = parse_search_request(request, session)
    query_str = params['query_str']
    page = params['page']
    threat_filter = params['threat_filter']
    time_range = params['time_range']
    custom_start = params['custom_start']
    custom_end = params['custom_end']
    sort_field = params['sort_field']
    sort_order = params['sort_order']
    
    results = []
    total_hits = 0
    error_message = None
    per_page = 50
    
    # Execute search
    if query_str:
        try:
            # Build OpenSearch query
            base_query = build_opensearch_query(query_str)
            
            # Build filters list using helper functions
            filters = []
            
            # Add threat filtering
            threat_query = build_threat_filter_query(threat_filter)
            if threat_query:
                filters.append(threat_query)
            
            # Add time range filtering
            time_query = build_time_filter_query(time_range, custom_start, custom_end)
            if time_query:
                filters.append(time_query)
            
            # Combine base query with filters
            if filters:
                os_query = {
                    "bool": {
                        "must": [base_query],
                        "filter": filters
                    }
                }
                print(f"[Search] Final query with filters: {os_query}")
            else:
                os_query = base_query
                print(f"[Search] Query without filters: {os_query}")
            
            # Search across all indices for this case
            from_offset = (page - 1) * per_page
            
            # Build sort configuration
            print(f"[Search] Sort parameters: field={sort_field}, order={sort_order}")
            if sort_field == 'timestamp':
                # Sort by timestamp using the date field mapping
                # Try both new (#attributes) and legacy (@) field names for backward compatibility
                sort_config = [
                    {
                        "System.TimeCreated.#attributes.SystemTime.date": {
                            "order": sort_order,
                            "unmapped_type": "date"
                        }
                    },
                    {
                        "System.TimeCreated.@SystemTime.date": {
                            "order": sort_order,
                            "unmapped_type": "date"
                        }
                    },
                    "_score"  # Secondary sort by relevance
                ]
                print(f"[Search] Using timestamp sort: {sort_order} (trying both new and legacy field names)")
            else:
                # Default: sort by relevance only
                sort_config = ["_score"]
                print(f"[Search] Using relevance sort")
            
            # Execute search (outside if/else blocks - runs for all sort types)
            search_body = {
                "query": os_query,
                "from": from_offset,
                "size": per_page,
                "sort": sort_config,
                "_source": True
            }
            
            response = opensearch_client.search(
                index=','.join(indices),
                body=search_body,
                ignore_unavailable=True
            )
            
            total_hits = response['hits']['total']['value']
            log_audit('search', 'search', f'Searched case {case.name} for "{query_str}" - {total_hits} results')
            
            # Add to search history
            try:
                history = SearchHistory(
                    user_id=current_user.id,
                    case_id=case.id,
                    query=query_str,
                    time_range=time_range,
                    violations_only=(threat_filter == 'sigma'),  # For backward compatibility
                    result_count=total_hits
                )
                db.session.add(history)
                db.session.commit()
            except:
                db.session.rollback()
            
            # Process search results using helper function
            for hit in response['hits']['hits']:
                source = hit['_source']
                
                # DEBUG: Print first few SIGMA results to see what fields exist
                if len(results) < 3 and threat_filter in ['sigma', 'either', 'both']:
                    print(f"[Search] DEBUG - Threat filter {threat_filter} result keys: {list(source.keys())[:30]}")
                    if '_casescope_metadata' in source:
                        print(f"[Search] DEBUG - Has metadata: {source['_casescope_metadata']}")
                    else:
                        print(f"[Search] DEBUG - NO _casescope_metadata field!")
                    if 'System.EventID' in source:
                        print(f"[Search] DEBUG - Has System.EventID")
                    if 'System.EventID.#text' in source:
                        print(f"[Search] DEBUG - Has System.EventID.#text")
                    print(f"[Search] DEBUG - Document ID: {hit['_id']}")
                
                # Extract standardized fields (uses dual-mapping aware helper)
                extracted = extract_event_fields(source, hit['_id'])
                
                # Check for IOC matches for this event
                ioc_matches = []
                try:
                    event_doc_id = hit['_id']
                    matches = db.session.query(IOCMatch).filter_by(
                        case_id=case.id,
                        event_id=event_doc_id
                    ).all()
                    
                    for match in matches:
                        ioc = match.ioc
                        ioc_matches.append({
                            'type': ioc.ioc_type,
                            'value': ioc.ioc_value,
                            'severity': ioc.severity
                        })
                except Exception as e:
                    print(f"[Search] Error checking IOC matches: {e}")
                
                # Add result to list with both extracted fields and additional data
                results.append({
                    'index': hit['_index'],
                    'id': hit['_id'],
                    'doc_id': hit['_id'],  # OpenSearch document ID for tagging
                    'score': hit['_score'],
                    'timestamp': extracted['timestamp'],
                    'event_id': extracted['event_id'],
                    'event_type': extracted['event_type'],
                    'source_file': extracted['source_file'],
                    'computer': extracted['computer'],
                    'channel': extracted['channel'],
                    'provider': extracted['provider'],
                    'full_data': source,
                    'sigma_violations': extracted['sigma_violations'],
                    'has_violations': extracted['has_violations'],
                    'ioc_matches': ioc_matches
                })
        
        except Exception as e:
            import traceback
            error_message = f"Search error: {str(e)}"
            print(f"[Search] Error: {e}")
            traceback.print_exc()
    
    # Get search history for this case (last 10)
    recent_searches = db.session.query(SearchHistory).filter_by(
        user_id=current_user.id, 
        case_id=case.id
    ).order_by(SearchHistory.executed_at.desc()).limit(10).all()
    
    # Get saved searches for this user/case
    saved_searches = db.session.query(SavedSearch).filter(
        SavedSearch.user_id == current_user.id,
        (SavedSearch.case_id == case.id) | (SavedSearch.case_id == None)
    ).order_by(SavedSearch.last_used.desc().nullslast(), SavedSearch.created_at.desc()).all()
    
    return render_search_page(case, query_str, results, total_hits, page, per_page, error_message, len(indexed_files), threat_filter, time_range, custom_start, custom_end, recent_searches, saved_searches, sort_field, sort_order)

@app.route('/search/save', methods=['POST'])
@login_required
def save_search():
    """Save a search query"""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        query = data.get('query', '').strip()
        case_id = data.get('case_id')
        time_range = data.get('time_range', 'all')
        custom_start = data.get('custom_start')
        custom_end = data.get('custom_end')
        violations_only = data.get('violations_only', False)
        
        if not name or not query:
            return jsonify({'success': False, 'message': 'Name and query required'}), 400
        
        # Parse datetime if custom range
        from datetime import datetime as dt
        cs = dt.fromisoformat(custom_start) if custom_start else None
        ce = dt.fromisoformat(custom_end) if custom_end else None
        
        saved = SavedSearch(
            user_id=current_user.id,
            case_id=case_id,
            name=name,
            query=query,
            time_range=time_range,
            custom_start=cs,
            custom_end=ce,
            violations_only=violations_only
        )
        db.session.add(saved)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'Search "{name}" saved'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/search/saved/<int:search_id>/load', methods=['POST'])
@login_required
def load_saved_search(search_id):
    """Load and execute a saved search"""
    try:
        saved = db.session.get(SavedSearch, search_id)
        if not saved or saved.user_id != current_user.id:
            return jsonify({'success': False, 'message': 'Search not found'}), 404
        
        # Update usage stats
        saved.last_used = datetime.utcnow()
        saved.use_count += 1
        db.session.commit()
        
        return jsonify({
            'success': True,
            'query': saved.query,
            'time_range': saved.time_range,
            'custom_start': saved.custom_start.isoformat() if saved.custom_start else None,
            'custom_end': saved.custom_end.isoformat() if saved.custom_end else None,
            'violations_only': saved.violations_only
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/search/saved/<int:search_id>/delete', methods=['POST'])
@login_required
def delete_saved_search(search_id):
    """Delete a saved search"""
    try:
        saved = db.session.get(SavedSearch, search_id)
        if not saved or saved.user_id != current_user.id:
            return jsonify({'success': False, 'message': 'Search not found'}), 404
        
        name = saved.name
        db.session.delete(saved)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'Deleted "{name}"'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/sigma-rules/download', methods=['POST'])
@login_required
def download_sigma_rules():
    """Download SIGMA rules from SigmaHQ GitHub repository"""
    import hashlib
    import tempfile
    import shutil
    import subprocess
    
    try:
        # Create temp directory for cloning
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = os.path.join(tmpdir, 'sigma')
            
            # Clone SigmaHQ repository (shallow clone for speed)
            flash('📥 Downloading SIGMA rules from GitHub...', 'info')
            result = subprocess.run(
                ['/usr/bin/git', 'clone', '--depth', '1', 'https://github.com/SigmaHQ/sigma.git', repo_path],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                flash(f'Error cloning repository: {result.stderr}', 'error')
                return redirect(url_for('sigma_rules'))
            
            # Parse and import rules from rules/ directory
            rules_dir = os.path.join(repo_path, 'rules')
            imported_count = 0
            skipped_count = 0
            error_count = 0
            
            if os.path.exists(rules_dir):
                import yaml
                
                for root, dirs, files in os.walk(rules_dir):
                    for file in files:
                        if file.endswith('.yml') or file.endswith('.yaml'):
                            file_path = os.path.join(root, file)
                            
                            try:
                                with open(file_path, 'r', encoding='utf-8') as f:
                                    yaml_content = f.read()
                                    rule_data = yaml.safe_load(yaml_content)
                                
                                # Skip non-detection rules
                                if not rule_data.get('detection'):
                                    continue
                                
                                # Calculate hash
                                rule_hash = hashlib.sha256(yaml_content.encode()).hexdigest()
                                
                                # Check if already exists
                                existing = db.session.query(SigmaRule).filter_by(rule_hash=rule_hash).first()
                                if existing:
                                    skipped_count += 1
                                    continue
                                
                                # Extract logsource
                                logsource = rule_data.get('logsource', {})
                                category = logsource.get('category', logsource.get('product', 'unknown'))
                                
                                # Auto-enable threat-hunting rules from rules-threat-hunting/windows directory
                                # Path format: .../sigma/rules/rules-threat-hunting/windows/...
                                is_threat_hunting = 'threat-hunting' in file_path and 'windows' in file_path.lower()
                                
                                # Create rule
                                rule = SigmaRule(
                                    name=rule_data.get('id', file.replace('.yml', '').replace('.yaml', '')),
                                    title=rule_data.get('title', 'Untitled Rule'),
                                    description=rule_data.get('description', ''),
                                    author=rule_data.get('author', 'SigmaHQ'),
                                    level=rule_data.get('level', 'medium'),
                                    status=rule_data.get('status', 'stable'),
                                    category=category,
                                    tags=json.dumps(rule_data.get('tags', [])),
                                    rule_yaml=yaml_content,
                                    rule_hash=rule_hash,
                                    is_builtin=False,
                                    is_enabled=is_threat_hunting,  # Auto-enable threat-hunting rules
                                    uploaded_by=current_user.id
                                )
                                
                                db.session.add(rule)
                                imported_count += 1
                                
                                # Commit every 100 rules
                                if imported_count % 100 == 0:
                                    db.session.commit()
                            
                            except Exception as e:
                                error_count += 1
                                continue
                
                # Final commit
                db.session.commit()
            
            # Count auto-enabled rules
            enabled_count = db.session.query(SigmaRule).filter_by(is_enabled=True).count()
            
            flash(f'✓ Import complete: {imported_count} new rules added ({enabled_count} enabled), {skipped_count} duplicates skipped, {error_count} errors', 'success')
            return redirect(url_for('sigma_rules'))
    
    except subprocess.TimeoutExpired:
        flash('Download timed out. Please try again.', 'error')
        return redirect(url_for('sigma_rules'))
    except Exception as e:
        flash(f'Error downloading rules: {str(e)}', 'error')
        return redirect(url_for('sigma_rules'))

@app.route('/sigma-rules', methods=['GET', 'POST'])
@login_required
def sigma_rules():
    """SIGMA Rules Management Interface"""
    import hashlib
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'upload':
            # Handle file upload
            if 'rule_file' not in request.files:
                flash('No file selected', 'error')
                return redirect(url_for('sigma_rules'))
            
            file = request.files['rule_file']
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(url_for('sigma_rules'))
            
            if not file.filename.endswith('.yml') and not file.filename.endswith('.yaml'):
                flash('Only YAML files (.yml, .yaml) are supported', 'error')
                return redirect(url_for('sigma_rules'))
            
            try:
                # Read YAML content
                yaml_content = file.read().decode('utf-8')
                
                # Parse YAML to extract metadata
                import yaml
                rule_data = yaml.safe_load(yaml_content)
                
                # Calculate hash
                rule_hash = hashlib.sha256(yaml_content.encode()).hexdigest()
                
                # Check for duplicates
                existing = db.session.query(SigmaRule).filter_by(rule_hash=rule_hash).first()
                if existing:
                    flash(f'Rule already exists: {existing.title}', 'warning')
                    return redirect(url_for('sigma_rules'))
                
                # Create new rule
                rule = SigmaRule(
                    name=rule_data.get('id', file.filename.replace('.yml', '').replace('.yaml', '')),
                    title=rule_data.get('title', 'Untitled Rule'),
                    description=rule_data.get('description', ''),
                    author=rule_data.get('author', 'Unknown'),
                    level=rule_data.get('level', 'medium'),
                    status=rule_data.get('status', 'experimental'),
                    category=rule_data.get('logsource', {}).get('category', 'unknown'),
                    tags=json.dumps(rule_data.get('tags', [])),
                    rule_yaml=yaml_content,
                    rule_hash=rule_hash,
                    is_builtin=False,
                    is_enabled=True,
                    uploaded_by=current_user.id
                )
                
                db.session.add(rule)
                db.session.commit()
                
                flash(f'✓ Rule uploaded successfully: {rule.title}', 'success')
                return redirect(url_for('sigma_rules'))
                
            except Exception as e:
                flash(f'Error uploading rule: {str(e)}', 'error')
                return redirect(url_for('sigma_rules'))
        
        elif action == 'toggle':
            # Toggle rule enabled/disabled
            rule_id = request.form.get('rule_id')
            rule = db.session.get(SigmaRule, rule_id)
            if rule:
                rule.is_enabled = not rule.is_enabled
                db.session.commit()
                status = 'enabled' if rule.is_enabled else 'disabled'
                flash(f'Rule {status}: {rule.title}', 'success')
            return redirect(url_for('sigma_rules'))
        
        elif action == 'delete':
            # Delete user-uploaded rule (not built-in)
            rule_id = request.form.get('rule_id')
            rule = db.session.get(SigmaRule, rule_id)
            if rule and not rule.is_builtin:
                db.session.delete(rule)
                db.session.commit()
                flash(f'Rule deleted: {rule.title}', 'success')
            elif rule and rule.is_builtin:
                flash('Cannot delete built-in rules', 'error')
            return redirect(url_for('sigma_rules'))
    
    # GET request - show all rules (search is client-side JavaScript)
    all_rules = db.session.query(SigmaRule).order_by(SigmaRule.is_builtin.desc(), SigmaRule.level.desc(), SigmaRule.title).all()
    enabled_count = db.session.query(SigmaRule).filter_by(is_enabled=True).count()
    total_count = db.session.query(SigmaRule).count()
    
    # Get violation statistics
    total_violations = db.session.query(SigmaViolation).count()
    critical_violations = db.session.query(SigmaViolation).join(SigmaRule).filter(SigmaRule.level == 'critical').count()
    high_violations = db.session.query(SigmaViolation).join(SigmaRule).filter(SigmaRule.level == 'high').count()
    
    return render_sigma_rules_page(all_rules, enabled_count, total_count, total_violations, critical_violations, high_violations)


def get_event_description(event_id, channel, provider, event_data):
    """
    Get a human-friendly description of what the event represents
    Based on Windows Event IDs from Ultimate Windows Security Encyclopedia
    Source: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
    """
    event_id_str = str(event_id) if event_id != 'N/A' else ''
    
    # Windows Security Events (expanded from Ultimate Windows Security)
    security_events = {
        # Event Log Events
        '1100': 'Event Logging Service Shut Down',
        '1102': 'Audit Log Cleared',
        '1104': 'Security Log Full',
        '1108': 'Event Logging Error',
        
        # System Integrity Events
        '4608': 'Windows Starting Up',
        '4609': 'Windows Shutting Down',
        '4616': 'System Time Changed',
        
        # Logon/Logoff Events
        '4624': 'Successful Logon',
        '4625': 'Failed Logon',
        '4634': 'Logoff',
        '4647': 'User Initiated Logoff',
        '4648': 'Logon with Explicit Credentials',
        '4649': 'Replay Attack Detected',
        
        # Special Privileges
        '4672': 'Special Privileges Assigned',
        
        # Account Management
        '4720': 'User Account Created',
        '4722': 'User Account Enabled',
        '4723': 'Password Change Attempted',
        '4724': 'Password Reset Attempted',
        '4725': 'User Account Disabled',
        '4726': 'User Account Deleted',
        '4738': 'User Account Changed',
        '4740': 'User Account Locked Out',
        '4767': 'User Account Unlocked',
        '4781': 'Account Name Changed',
        
        # Group Management
        '4727': 'Global Security Group Created',
        '4728': 'Member Added to Global Security Group',
        '4729': 'Member Removed from Global Security Group',
        '4730': 'Global Security Group Deleted',
        '4731': 'Local Security Group Created',
        '4732': 'Member Added to Local Security Group',
        '4733': 'Member Removed from Local Security Group',
        '4734': 'Local Security Group Deleted',
        '4735': 'Security Group Changed',
        '4737': 'Security Group Changed',
        '4754': 'Universal Security Group Created',
        '4755': 'Universal Security Group Changed',
        '4756': 'Member Added to Universal Security Group',
        '4757': 'Member Removed from Universal Security Group',
        '4758': 'Universal Security Group Deleted',
        
        # Process Tracking
        '4688': 'Process Created',
        '4689': 'Process Terminated',
        
        # Object Access
        '4656': 'Handle to Object Requested',
        '4657': 'Registry Value Modified',
        '4658': 'Handle to Object Closed',
        '4660': 'Object Deleted',
        '4663': 'Attempt to Access Object',
        '4670': 'Permissions on Object Changed',
        
        # Policy Changes
        '4704': 'User Right Assigned',
        '4705': 'User Right Removed',
        '4706': 'Trust to Domain Created',
        '4707': 'Trust to Domain Removed',
        '4713': 'Kerberos Policy Changed',
        '4719': 'System Audit Policy Changed',
        '4739': 'Domain Policy Changed',
        '4817': 'Auditing Settings Changed',
        
        # Network Share Access
        '5140': 'Network Share Accessed',
        '5142': 'Network Share Created',
        '5143': 'Network Share Modified',
        '5144': 'Network Share Deleted',
        '5145': 'Network Share Checked',
        
        # Windows Firewall
        '4946': 'Windows Firewall Exception List Changed',
        '4947': 'Windows Firewall Rule Modified',
        '4948': 'Windows Firewall Rule Deleted',
        '4950': 'Windows Firewall Setting Changed',
        '4954': 'Windows Firewall Group Policy Changed',
        '4956': 'Windows Firewall Active Profile Changed',
        
        # Account Logon
        '4768': 'Kerberos TGT Requested',
        '4769': 'Kerberos Service Ticket Requested',
        '4770': 'Kerberos Service Ticket Renewed',
        '4771': 'Kerberos Pre-Authentication Failed',
        '4776': 'Domain Controller Validated Credentials',
        '4777': 'Domain Controller Failed to Validate Credentials'
    }
    
    # System Events
    system_events = {
        '1074': 'System Shutdown/Restart Initiated',
        '6005': 'Event Log Service Started',
        '6006': 'Event Log Service Stopped',
        '6008': 'Unexpected Shutdown',
        '6009': 'System Information',
        '6013': 'System Uptime',
        '7034': 'Service Crashed Unexpectedly',
        '7035': 'Service Control Event',
        '7036': 'Service State Changed',
        '7040': 'Service Startup Type Changed',
        '7045': 'Service Installed'
    }
    
    # PowerShell Events
    powershell_events = {
        '4103': 'PowerShell Module Logging',
        '4104': 'PowerShell Script Block Logging',
        '4105': 'PowerShell Script Start',
        '4106': 'PowerShell Script Stop',
        '800': 'PowerShell Pipeline Execution',
        '403': 'PowerShell Engine State Changed',
        '600': 'PowerShell Provider Started'
    }
    
    # Windows Defender Events
    defender_events = {
        '1000': 'Defender Scan Started',
        '1001': 'Defender Scan Completed',
        '1002': 'Defender Scan Stopped',
        '1005': 'Defender Scan Failed',
        '1006': 'Defender Malware Detected',
        '1007': 'Defender Action Taken',
        '1008': 'Defender Action Failed',
        '1009': 'Defender Restored Quarantined Item',
        '1010': 'Defender Deleted Quarantined Item',
        '1011': 'Defender Restore Failed',
        '1012': 'Defender Delete Failed',
        '1013': 'Defender History Deleted',
        '1015': 'Defender Suspicious Behavior Detected',
        '1116': 'Defender Malware Detected',
        '1117': 'Defender Malware Action Taken',
        '1118': 'Defender Malware Action Failed',
        '1119': 'Defender Critical Malware Detected',
        '1150': 'Defender Definition Updated',
        '1151': 'Defender Signature Updated',
        '2000': 'Defender Definition Update Started',
        '2001': 'Defender Definition Update Failed',
        '2003': 'Defender Engine Updated',
        '2004': 'Defender Engine Update Failed',
        '3002': 'Defender Real-Time Protection Error',
        '5001': 'Defender Real-Time Protection Disabled',
        '5004': 'Defender Real-Time Protection Config Changed',
        '5007': 'Defender Configuration Changed',
        '5010': 'Defender Scan Disabled',
        '5012': 'Defender Tamper Protection Changed'
    }
    
    # Check event ID in our mappings
    if event_id_str in security_events:
        return security_events[event_id_str]
    elif event_id_str in system_events:
        return system_events[event_id_str]
    elif event_id_str in powershell_events:
        return powershell_events[event_id_str]
    elif event_id_str in defender_events:
        return defender_events[event_id_str]
    
    # Fallback to provider-based description
    if provider and provider != 'N/A':
        if 'Defender' in provider:
            return 'Windows Defender Event'
        elif 'PowerShell' in provider:
            return 'PowerShell Activity'
        elif 'Security' in str(channel):
            return 'Security Event'
        elif 'System' in str(channel):
            return 'System Event'
        elif 'Application' in str(channel):
            return 'Application Event'
    
    # Final fallback
    if event_id_str:
        return f'Event ID {event_id_str}'
    
    return 'Unknown Event'


def render_sidebar_menu(active_page=''):
    """
    Centralized sidebar menu rendering
    Args:
        active_page: The current page identifier (e.g., 'dashboard', 'upload', 'files', 'search')
    """
    return f'''
<h3 class="menu-title">Navigation</h3>
<a href="/dashboard" class="menu-item {'active' if active_page == 'dashboard' else ''}">📊 System Dashboard</a>
<a href="/case/dashboard" class="menu-item {'active' if active_page == 'case_dashboard' else ''}">🎯 Case Dashboard</a>
<a href="/case/select" class="menu-item {'active' if active_page == 'case_select' else ''}">📁 Case Selection</a>
<a href="/upload" class="menu-item {'active' if active_page == 'upload' else ''}">📤 Upload Files</a>
<a href="/files" class="menu-item {'active' if active_page == 'files' else ''}">📄 List Files</a>
<a href="/search" class="menu-item {'active' if active_page == 'search' else ''}">🔍 Search Events</a>
<a href="/violations" class="menu-item {'active' if active_page == 'violations' else ''}">🚨 SIGMA Violations</a>
<a href="/ioc/list" class="menu-item {'active' if active_page == 'ioc_management' else ''}">🎯 IOC Management</a>
<a href="/ioc/matches" class="menu-item {'active' if active_page == 'ioc_matches' else ''}">🔎 IOC Matches</a>

<h3 class="menu-title">Management</h3>
<a href="/case-management" class="menu-item {'active' if active_page == 'case_management' else ''}">⚙️ Case Management</a>
<a href="/file-management" class="menu-item {'active' if active_page == 'file_management' else ''}">🗂️ File Management</a>
<a href="/users" class="menu-item {'active' if active_page == 'user_management' else ''}">👥 User Management</a>
<a href="/audit-log" class="menu-item {'active' if active_page == 'audit_log' else ''}">📜 Audit Log</a>
<a href="/sigma-rules" class="menu-item {'active' if active_page == 'sigma_rules' else ''}">📋 SIGMA Rules</a>
<a href="/settings" class="menu-item {'active' if active_page == 'settings' else ''}">⚙️ System Settings</a>
<a href="/update-event-ids" class="menu-item" onclick="return confirm('Updating Event IDs will add new event descriptions. After updating, you should Re-index all files to apply the new descriptions. Continue?')">🔄 Update Event ID Database</a>
    '''


def build_opensearch_query(user_query):
    """
    Build OpenSearch query from user input
    Supports: AND, OR, NOT, parentheses, phrase matching with quotes
    Case-insensitive by default
    
    Smart field mapping:
    - EventID -> System.EventID
    - Computer -> System.Computer
    - Channel -> System.Channel
    """
    # Work on a copy to avoid modifying the original
    query_str = user_query.strip()
    
    # Map common field names to actual indexed field names
    # This makes queries more user-friendly
    # Fields use DOT notation as stored by flatten_event() in tasks.py
    field_mappings = {
        # EVTX Windows Event Log fields
        'EventID': 'System.EventID.#text',
        'Computer': 'System.Computer',
        'Channel': 'System.Channel',
        'Provider': 'System.Provider.#attributes.Name',
        'Level': 'System.Level',
        'Task': 'System.Task',
        'TimeCreated': 'System.TimeCreated.#attributes.SystemTime',
        'source_filename': '_casescope_metadata.filename',
        'filename': '_casescope_metadata.filename',  # Alternative field name
        
        # EDR/NDJSON Process fields (Huntress, Crowdstrike, etc.)
        'CommandLine': 'process.command_line',
        'ProcessName': 'process.name',
        'ProcessPath': 'process.executable',
        'ProcessPID': 'process.pid',
        'ParentProcess': 'process.parent.name',
        'ParentPID': 'process.parent.pid',
        'Username': 'process.user.name',
        'UserDomain': 'process.user.domain',
        'Hostname': 'host.hostname',
        'HostIP': 'host.ip',
        'Hash': 'process.hash.sha256'
    }
    
    # Replace field names in query (simple string replacement)
    for user_field, indexed_field in field_mappings.items():
        # Match field: pattern (case insensitive)
        import re
        query_str = re.sub(
            rf'\b{user_field}\s*:',
            f'{indexed_field}:',
            query_str,
            flags=re.IGNORECASE
        )
    
    # For phase 1, use query_string query which supports most operators
    # Case-insensitive by default for analyzed text fields
    return {
        "query_string": {
            "query": query_str,
            "default_operator": "AND",
            "analyze_wildcard": True,
            "fields": ["*"],
            "lenient": True
        }
    }

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').lower().strip()
        password = request.form.get('password', '')
        
        # Debug logging
        print(f"DEBUG: Login attempt - Username: '{username}', Password length: {len(password)}")
        print(f"DEBUG: Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
        print(f"DEBUG: Request method: {request.method}")
        print(f"DEBUG: Form data: {dict(request.form)}")
        
        try:
            # Check if database exists and is accessible
            user_count = db.session.query(User).count()
            print(f"DEBUG: Total users in database: {user_count}")
            
            # Look for the user
            user = db.session.query(User).filter(db.func.lower(User.username) == username).first()
            print(f"DEBUG: User found: {user is not None}")
            
            if user:
                print(f"DEBUG: User details - ID: {user.id}, Username: {user.username}, Active: {user.is_active}")
                password_valid = user.check_password(password)
                print(f"DEBUG: Password valid: {password_valid}")
                
                if password_valid and user.is_active:
                    login_user(user)
                    print(f"DEBUG: User logged in successfully")
                    log_audit('login', 'authentication', f'User {username} logged in successfully')
                    if user.force_password_change:
                        flash('You must change your password before continuing.', 'warning')
                        return redirect(url_for('change_password'))
                    return redirect(url_for('dashboard'))
                else:
                    print(f"DEBUG: Login failed - Password valid: {password_valid}, User active: {user.is_active}")
                    log_audit('login_failed', 'authentication', f'Failed login attempt for {username}', success=False, username=username)
                    flash('Invalid username or password.', 'error')
            else:
                print(f"DEBUG: No user found with username: '{username}'")
                log_audit('login_failed', 'authentication', f'Failed login attempt for non-existent user {username}', success=False, username=username)
                # List all users for debugging
                all_users = db.session.query(User).all()
                print(f"DEBUG: All users in database: {[u.username for u in all_users]}")
                flash('Invalid username or password.', 'error')
                
        except Exception as e:
            print(f"DEBUG: Database error during login: {e}")
            import traceback
            traceback.print_exc()
            flash('Database error. Please check system logs.', 'error')
    
    # Get flash messages for display on login page
    from flask import get_flashed_messages
    flash_messages = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        flash_messages += f'<div class="alert alert-{category}">{message}</div>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>caseScope 7.1 - Login</title>
        {get_theme_css()}    </head>
    <body>
        <div class="login-container">
            <div class="logo"><span class="case">case</span><span class="scope">Scope</span></div>
            {flash_messages}
            <form method="POST">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Username" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit">Login</button>
            </form>
            <div class="version">Version {APP_VERSION}</div>
        </div>
    </body>
    </html>
    '''

@app.route('/logout')
@login_required
def logout():
    log_audit('logout', 'authentication', f'User {current_user.username} logged out')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    clear_search_filters()  # Clear search filters when leaving search page
    # Get real system statistics
    total_cases = db.session.query(Case).count()
    total_files = db.session.query(CaseFile).filter_by(is_deleted=False).count()
    total_indexed = db.session.query(CaseFile).filter_by(is_deleted=False, is_indexed=True).count()
    total_events = db.session.query(db.func.sum(CaseFile.event_count)).filter_by(is_deleted=False).scalar() or 0
    total_storage = db.session.query(db.func.sum(CaseFile.file_size)).filter_by(is_deleted=False).scalar() or 0
    total_violations = db.session.query(db.func.sum(CaseFile.violation_count)).filter_by(is_deleted=False).scalar() or 0
    
    # Get user count
    total_users = db.session.query(User).count()
    
    # SIGMA Rules statistics
    total_sigma_rules = db.session.query(SigmaRule).count()
    enabled_sigma_rules = db.session.query(SigmaRule).filter_by(is_enabled=True).count()
    latest_rule = db.session.query(SigmaRule).order_by(SigmaRule.created_at.desc()).first()
    last_rule_update = latest_rule.created_at.strftime('%Y-%m-%d') if latest_rule else 'Never'
    
    # IOC statistics
    total_iocs = db.session.query(IOC).count()
    total_ioc_matches = db.session.query(IOCMatch).count()
    
    # System resource metrics
    ram = psutil.virtual_memory()
    ram_used_gb = ram.used / (1024**3)
    ram_total_gb = ram.total / (1024**3)
    ram_percent = ram.percent
    cpu_percent = psutil.cpu_percent(interval=0.1)
    
    # System versions
    try:
        import sqlite3
        sqlite_version = sqlite3.sqlite_version
    except:
        sqlite_version = "Unknown"
    
    try:
        opensearch_info = opensearch_client.info()
        opensearch_version = opensearch_info.get('version', {}).get('number', 'Unknown')
    except:
        opensearch_version = "Unknown"
    
    sqlalchemy_version = sqlalchemy.__version__
    
    # Get Flask version (handle both old and new Flask versions)
    try:
        import flask
        flask_version = flask.__version__
    except:
        flask_version = "Unknown"
    
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    
    # Recent activity
    recent_cases = db.session.query(Case).order_by(Case.created_at.desc()).limit(5).all()
    recent_files = db.session.query(CaseFile).filter_by(is_deleted=False).order_by(CaseFile.uploaded_at.desc()).limit(5).all()
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>caseScope 7.2 - Dashboard</title>
        {get_theme_css()}    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            {render_sidebar_menu('dashboard')}
        </div>
        <div class="main-content">
            <div class="header">
                <div class="case-title">🎯 System Dashboard</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="{url_for('logout')}" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                <div class="tiles">
                    <div class="tile">
                        <h3>📈 System Statistics</h3>
                        <p><strong>Total Cases:</strong> {total_cases:,}</p>
                        <p><strong>Total Files:</strong> {total_files:,} ({total_indexed:,} indexed)</p>
                        <p><strong>Total Events:</strong> {total_events:,}</p>
                        <p><strong>Total Users:</strong> {total_users}</p>
                        <p><strong>RAM:</strong> <span id="ram-usage">{ram_used_gb:.1f} GB / {ram_total_gb:.1f} GB ({ram_percent:.1f}%)</span></p>
                        <p><strong>CPU:</strong> <span id="cpu-usage">{cpu_percent:.1f}%</span></p>
                    </div>
                    <div class="tile">
                        <h3>💾 Storage & Analysis</h3>
                        <p><strong>Storage Used:</strong> {total_storage / (1024*1024*1024):.2f} GB</p>
                        <p><strong>Indexed Files:</strong> {total_indexed:,} / {total_files:,}</p>
                        <p><strong>SIGMA Violations:</strong> {total_violations:,}</p>
                        <p><strong>IOC Matches:</strong> {total_ioc_matches:,}</p>
                    </div>
                    <div class="tile">
                        <h3>📋 SIGMA Rules</h3>
                        <p><strong>Total Rules:</strong> {total_sigma_rules:,}</p>
                        <p><strong>Enabled:</strong> <span style="color: #4caf50; font-weight: 600;">{enabled_sigma_rules:,}</span> / {total_sigma_rules:,}</p>
                        <p><strong>Last Updated:</strong> {last_rule_update}</p>
                        <p><strong>IOCs Tracked:</strong> {total_iocs:,}</p>
                        <p style="margin-top: 15px;"><a href="/sigma-rules" style="color: #4caf50;">→ Manage Rules</a></p>
                    </div>
                    <div class="tile">
                        <h3>⚙️ System Versions</h3>
                        <p><strong>Python:</strong> {python_version}</p>
                        <p><strong>Flask:</strong> {flask_version}</p>
                        <p><strong>SQLAlchemy:</strong> {sqlalchemy_version}</p>
                        <p><strong>SQLite:</strong> {sqlite_version}</p>
                        <p><strong>OpenSearch:</strong> {opensearch_version}</p>
                        <p><strong>caseScope:</strong> {APP_VERSION}</p>
                    </div>
                </div>
                
                <div class="tiles" style="margin-top: 30px;">
                    <div class="tile">
                        <h3>📋 Recent Cases</h3>
                        {''.join([f'<p>📁 <a href="/case/select">{case.name}</a> - {case.created_at.strftime("%Y-%m-%d %H:%M")}</p>' for case in recent_cases[:5]]) if recent_cases else '<p style="color: #aaa;">No cases yet</p>'}
                        <p style="margin-top: 15px;"><a href="/case/select" style="color: #4caf50;">→ View All Cases</a></p>
                    </div>
                    <div class="tile">
                        <h3>📄 Recent File Uploads</h3>
                        {''.join([f'<p>📄 {file.original_filename[:30]}... ({file.file_size / (1024*1024):.1f} MB)</p>' for file in recent_files[:5]]) if recent_files else '<p style="color: #aaa;">No files uploaded yet</p>'}
                        <p style="margin-top: 15px;"><a href="/files" style="color: #4caf50;">→ View All Files</a></p>
                    </div>
                </div>
            </div>
        </div>
        <div class="footer">
            Copyright (c) 2025 Justin Dube | <a href="mailto:casescope@thedubes.net">casescope@thedubes.net</a>
        </div>
        
        <script>
            // Auto-update system metrics every 3 seconds
            function updateSystemMetrics() {{
                fetch('/api/system-metrics')
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) {{
                            // Update RAM
                            document.getElementById('ram-usage').textContent = 
                                data.ram_used_gb.toFixed(1) + ' GB / ' + 
                                data.ram_total_gb.toFixed(1) + ' GB (' + 
                                data.ram_percent.toFixed(1) + '%)';
                            
                            // Update CPU
                            document.getElementById('cpu-usage').textContent = 
                                data.cpu_percent.toFixed(1) + '%';
                        }}
                    }})
                    .catch(error => {{
                        console.error('Error fetching system metrics:', error);
                    }});
            }}
            
            // Update every 3 seconds
            setInterval(updateSystemMetrics, 3000);
        </script>
    </body>
    </html>
    '''

@app.route('/api/system-metrics')
@login_required
def api_system_metrics():
    """API endpoint for real-time system metrics"""
    try:
        ram = psutil.virtual_memory()
        ram_used_gb = ram.used / (1024**3)
        ram_total_gb = ram.total / (1024**3)
        ram_percent = ram.percent
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        return jsonify({
            'success': True,
            'ram_used_gb': ram_used_gb,
            'ram_total_gb': ram_total_gb,
            'ram_percent': ram_percent,
            'cpu_percent': cpu_percent
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'error')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'error')
        elif len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
        else:
            current_user.set_password(new_password)
            current_user.force_password_change = False
            db.session.commit()
            flash('Password changed successfully.', 'success')
            return redirect(url_for('dashboard'))
    
    # Get flash messages for display on change password page
    from flask import get_flashed_messages
    flash_messages = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        flash_messages += f'<div class="alert alert-{category}">{message}</div>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Change Password - caseScope 7.1</title>
        {get_theme_css()}    </head>
    <body>
        <div class="container">
            <div class="logo"><span class="case">case</span><span class="scope">Scope</span></div>
            <h2>Change Password</h2>
            <p>You must change your password before continuing.</p>
            {flash_messages}
            <form method="POST">
                <div class="form-group">
                    <input type="password" name="current_password" placeholder="Current Password" required>
                </div>
                <div class="form-group">
                    <input type="password" name="new_password" placeholder="New Password (min 8 characters)" required>
                </div>
                <div class="form-group">
                    <input type="password" name="confirm_password" placeholder="Confirm New Password" required>
                </div>
                <button type="submit">Change Password</button>
            </form>
        </div>
    </body>
    </html>
    '''

# UI Rendering Functions
def render_upload_form(case):
    """Render professional file upload form with drag-and-drop"""
    # Get flash messages
    from flask import get_flashed_messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Upload Files - {case.name} - caseScope {APP_VERSION}</title>
        {get_theme_css()}
    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            {render_sidebar_menu('upload')}
        </div>
        
        <div class="main-content">
            <div class="header">
                <div class="case-title">📤 Upload Files</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            
            <div class="content">
                <div class="upload-page-container">
                    {flash_messages_html}
                    
                    <div class="upload-info-card">
                        <h3>📋 Upload Limits</h3>
                        <ul>
                            <li>Maximum 5 files per upload</li>
                            <li>Maximum 3GB per file</li>
                            <li>Duplicate detection via SHA256 hash</li>
                            <li>Supported formats: .evtx (Windows Event Logs), .ndjson (EDR telemetry), .json, .csv, .log, .txt, .xml</li>
                        </ul>
                    </div>
                    
                    <form method="POST" enctype="multipart/form-data" id="uploadForm">
                        <div class="upload-dropzone" id="dropzone">
                            <div class="upload-dropzone-content">
                                <div class="upload-icon">📁</div>
                                <div class="upload-primary-text">Click to select files or drag and drop</div>
                                <div class="upload-secondary-text">Up to 5 files, 3GB each</div>
                                <input type="file" id="fileInput" name="files" multiple accept=".evtx,.ndjson,.json,.csv,.log,.txt,.xml" style="display: none;">
                            </div>
                        </div>
                        
                        <div id="fileList" class="file-list" style="display: none;">
                            <h3>Selected Files (<span id="fileCount">0</span>)</h3>
                            <div id="fileItems"></div>
                        </div>
                        
                        <div class="upload-actions" id="uploadActions" style="display: none;">
                            <button type="submit" class="btn btn-primary">
                                <span>📤 Upload Files</span>
                            </button>
                            <button type="button" class="btn btn-secondary" onclick="clearFiles()">
                                <span>🗑️ Clear All</span>
                            </button>
                            <a href="/files" class="btn">
                                <span>← Back to Files</span>
                            </a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <script>
            const dropzone = document.getElementById('dropzone');
            const fileInput = document.getElementById('fileInput');
            const fileList = document.getElementById('fileList');
            const fileItems = document.getElementById('fileItems');
            const fileCount = document.getElementById('fileCount');
            const uploadActions = document.getElementById('uploadActions');
            
            // Click to select files
            dropzone.addEventListener('click', () => {{
                fileInput.click();
            }});
            
            // Drag and drop handlers
            dropzone.addEventListener('dragover', (e) => {{
                e.preventDefault();
                dropzone.classList.add('dragover');
            }});
            
            dropzone.addEventListener('dragleave', () => {{
                dropzone.classList.remove('dragover');
            }});
            
            dropzone.addEventListener('drop', (e) => {{
                e.preventDefault();
                dropzone.classList.remove('dragover');
                
                const files = e.dataTransfer.files;
                if (files.length > 0) {{
                    fileInput.files = files;
                    displayFiles(files);
                }}
            }});
            
            // File input change handler
            fileInput.addEventListener('change', (e) => {{
                displayFiles(e.target.files);
            }});
            
            function displayFiles(files) {{
                if (files.length === 0) {{
                    fileList.style.display = 'none';
                    uploadActions.style.display = 'none';
                    return;
                }}
                
                // Check file count limit
                if (files.length > 5) {{
                    alert('Maximum 5 files allowed per upload. Please select fewer files.');
                    fileInput.value = '';
                    return;
                }}
                
                fileItems.innerHTML = '';
                fileCount.textContent = files.length;
                
                let totalSize = 0;
                const maxSize = 3221225472; // 3GB in bytes
                
                for (let i = 0; i < files.length; i++) {{
                    const file = files[i];
                    totalSize += file.size;
                    
                    // Check individual file size
                    const sizeGB = (file.size / 1073741824).toFixed(2);
                    const sizeMB = (file.size / 1048576).toFixed(2);
                    const sizeDisplay = file.size > 1073741824 ? sizeGB + ' GB' : sizeMB + ' MB';
                    
                    const isOverSize = file.size > maxSize;
                    const fileClass = isOverSize ? 'file-item-error' : 'file-item';
                    
                    const fileItem = document.createElement('div');
                    fileItem.className = fileClass;
                    fileItem.innerHTML = `
                        <div class="file-item-icon">📄</div>
                        <div class="file-item-details">
                            <div class="file-item-name">${{file.name}}</div>
                            <div class="file-item-size">${{sizeDisplay}}${{isOverSize ? ' - ⚠️ Exceeds 3GB limit' : ''}}</div>
                        </div>
                        <div class="file-item-remove" onclick="removeFile(${{i}})">✕</div>
                    `;
                    fileItems.appendChild(fileItem);
                }}
                
                fileList.style.display = 'block';
                uploadActions.style.display = 'flex';
                
                // Show total size
                const totalSizeGB = (totalSize / 1073741824).toFixed(2);
                const totalSizeMB = (totalSize / 1048576).toFixed(2);
                const totalDisplay = totalSize > 1073741824 ? totalSizeGB + ' GB' : totalSizeMB + ' MB';
                
                const totalInfo = document.createElement('div');
                totalInfo.className = 'file-list-total';
                totalInfo.textContent = `Total size: ${{totalDisplay}}`;
                fileItems.appendChild(totalInfo);
            }}
            
            function removeFile(index) {{
                const dt = new DataTransfer();
                const files = fileInput.files;
                
                for (let i = 0; i < files.length; i++) {{
                    if (i !== index) {{
                        dt.items.add(files[i]);
                    }}
                }}
                
                fileInput.files = dt.files;
                displayFiles(fileInput.files);
            }}
            
            function clearFiles() {{
                fileInput.value = '';
                fileItems.innerHTML = '';
                fileList.style.display = 'none';
                uploadActions.style.display = 'none';
            }}
            
            // AJAX upload with progress bar
            document.getElementById('uploadForm').addEventListener('submit', (e) => {{
                e.preventDefault();
                
                if (fileInput.files.length === 0) {{
                    alert('Please select at least one file to upload.');
                    return false;
                }}
                
                // Check for oversized files
                for (let i = 0; i < fileInput.files.length; i++) {{
                    if (fileInput.files[i].size > 3221225472) {{
                        alert(`File "${{fileInput.files[i].name}}" exceeds the 3GB limit. Please remove it and try again.`);
                        return false;
                    }}
                }}
                
                // Create progress display
                const submitBtn = e.target.querySelector('button[type="submit"]');
                submitBtn.disabled = true;
                
                const progressHTML = '<div id="uploadProgress" style="margin-top: 20px; padding: 20px; background: #2a2a2a; border-radius: 8px;"><div style="margin-bottom: 10px; font-weight: bold;">Uploading files...</div><div style="background: #1a1a1a; border-radius: 4px; height: 30px; position: relative; overflow: hidden;"><div id="progressBar" style="height: 100%; background: linear-gradient(90deg, #1565c0, #42a5f5); width: 0%; transition: width 0.3s;"></div><div id="progressText" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); color: white; font-weight: bold;">0%</div></div></div>';
                submitBtn.insertAdjacentHTML('afterend', progressHTML);
                submitBtn.style.display = 'none';
                
                // Prepare form data
                const formData = new FormData(e.target);
                
                // Create AJAX request
                const xhr = new XMLHttpRequest();
                
                // Upload progress handler
                xhr.upload.addEventListener('progress', (event) => {{
                    if (event.lengthComputable) {{
                        const percentComplete = Math.round((event.loaded / event.total) * 100);
                        document.getElementById('progressBar').style.width = percentComplete + '%';
                        document.getElementById('progressText').textContent = percentComplete + '%';
                    }}
                }});
                
                // Upload complete handler
                xhr.addEventListener('load', () => {{
                    if (xhr.status === 200) {{
                        window.location.reload();
                    }} else {{
                        alert('Upload failed: ' + xhr.statusText);
                        submitBtn.style.display = 'block';
                        submitBtn.disabled = false;
                        document.getElementById('uploadProgress').remove();
                    }}
                }});
                
                // Error handler
                xhr.addEventListener('error', () => {{
                    alert('Upload error occurred');
                    submitBtn.style.display = 'block';
                    submitBtn.disabled = false;
                    document.getElementById('uploadProgress').remove();
                }});
                
                // Send request
                xhr.open('POST', window.location.href, true);
                xhr.send(formData);
                
                return false;
            }});
        </script>
    </body>
    </html>
    '''

def render_file_list(case, files):
    """Render file list for case"""
    # Get flash messages
    from flask import get_flashed_messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    # Get IOC match counts for all files
    from sqlalchemy import func
    ioc_counts = {}
    if files:
        # IOCMatch uses source_filename, not file_id, so we need to join with CaseFile
        ioc_count_results = db.session.query(
            CaseFile.id.label('file_id'),
            func.count(func.distinct(IOCMatch.event_id)).label('ioc_count')
        ).join(
            IOCMatch, 
            (IOCMatch.source_filename == CaseFile.original_filename) & 
            (IOCMatch.case_id == CaseFile.case_id)
        ).filter(
            CaseFile.case_id == case.id,
            CaseFile.is_deleted == False
        ).group_by(CaseFile.id).all()
        
        for file_id, count in ioc_count_results:
            ioc_counts[file_id] = count
    
    file_rows = ""
    for file in files:
        file_size_mb = file.file_size / (1024 * 1024)
        status_class = file.indexing_status.lower().replace(' ', '-')
        
        # Determine status display with progress - will be updated via JavaScript
        # STATUS COLORS: Queued=#9ca3af, Indexing=#ff9800, SIGMA=#fbbf24, IOC=#60a5fa, Complete=#4caf50, Failed=#f44336
        if file.indexing_status == 'Queued':
            status_html = '''<div id="status-{0}" class="status-text" data-file-id="{0}">
                <div style="font-weight: 600; color: #9ca3af;">Queued</div>
            </div>'''.format(file.id)
            status_display = status_html
            status_class = 'queued'
        elif file.indexing_status == 'Estimating':
            status_html = '''<div id="status-{0}" class="status-text" data-file-id="{0}">
                <div style="font-weight: 600; color: #9ca3af;">Estimating...</div>
            </div>'''.format(file.id)
            status_display = status_html
            status_class = 'estimating'
        elif file.indexing_status == 'Indexing':
            # Show current/total counts - updated every 5s
            estimated = file.estimated_event_count or int((file.file_size / 1048576) * 1000)
            current_events = file.event_count or 0
            
            status_html = '''<div id="status-{0}" class="status-text" data-file-id="{0}">
                <div style="font-weight: 600; color: #ff9800;">Indexing...</div>
                <div id="events-{0}" style="font-size: 0.9em; color: rgba(255,255,255,0.8); margin-top: 4px;">{1:,} / {2:,} events</div>
            </div>'''.format(file.id, current_events, estimated)
            status_display = status_html
            status_class = 'indexing'
        elif file.indexing_status == 'SIGMA Hunting':
            status_html = '''<div id="status-{0}" class="status-text" data-file-id="{0}">
                <div style="font-weight: 600; color: #fbbf24;">SIGMA Hunting...</div>
                <div id="sigma-progress-{0}" style="font-size: 0.9em; color: rgba(255,255,255,0.8); margin-top: 4px;">Processing...</div>
            </div>'''.format(file.id)
            status_display = status_html
            status_class = 'sigma-hunting'
        elif file.indexing_status == 'IOC Hunting':
            status_html = '''<div id="status-{0}" class="status-text" data-file-id="{0}">
                <div style="font-weight: 600; color: #60a5fa;">IOC Hunting...</div>
                <div id="ioc-progress-{0}" style="font-size: 0.9em; color: rgba(255,255,255,0.8); margin-top: 4px;">Processing...</div>
            </div>'''.format(file.id)
            status_display = status_html
            status_class = 'ioc-hunting'
        elif file.indexing_status == 'Completed':
            status_html = '''<div id="status-{0}" class="status-text">
                <div style="font-weight: 600; color: #4caf50;">Completed</div>
            </div>'''.format(file.id)
            status_display = status_html
            status_class = 'completed'
        elif file.indexing_status == 'Failed':
            status_html = '''<div id="status-{0}" class="status-text">
                <div style="font-weight: 600; color: #f44336;">Failed</div>
            </div>'''.format(file.id)
            status_display = status_html
            status_class = 'failed'
        else:
            status_display = '<div id="status-{0}" class="status-text">{1}</div>'.format(file.id, file.indexing_status)
        
        # Event count display - update dynamically with ID for JavaScript
        if file.event_count and file.event_count > 0:
            events_display = f'<span id="event-count-{file.id}">{file.event_count:,}</span>'
        else:
            events_display = f'<span id="event-count-{file.id}">-</span>'
        
        # Violations count
        if file.violation_count and file.violation_count > 0:
            violations_display = f'<span id="violation-count-{file.id}">{file.violation_count:,}</span>'
        else:
            violations_display = f'<span id="violation-count-{file.id}">-</span>'
        
        # IOC match count
        ioc_count = ioc_counts.get(file.id, 0)
        if ioc_count > 0:
            iocs_display = f'<span id="ioc-count-{file.id}">{ioc_count:,}</span>'
        else:
            iocs_display = f'<span id="ioc-count-{file.id}">-</span>'
        
        # Build action buttons based on user role
        actions_list = []
        actions_list.append(f'<button class="btn-action btn-info" onclick="showFileDetails({file.id})">📋 Details</button>')
        
        # Re-index available for any file (will reset and restart indexing)
        actions_list.append(f'<button class="btn-action btn-reindex" onclick="confirmReindex({file.id})">🔄 Re-index</button>')
        
        # Re-run Rules only available for indexed files
        if file.is_indexed and file.indexing_status in ['SIGMA Hunting', 'IOC Hunting', 'Completed', 'Failed']:
            actions_list.append(f'<button class="btn-action btn-rules" onclick="confirmRerunRules({file.id})">⚡ Re-run Rules</button>')
        
        # Re-hunt IOCs only available for indexed files
        if file.is_indexed and file.indexing_status in ['SIGMA Hunting', 'IOC Hunting', 'Completed', 'Failed']:
            actions_list.append(f'<button class="btn-action btn-iocs" onclick="confirmRehuntIocs({file.id})">🎯 Re-hunt IOCs</button>')
        
        if current_user.role == 'administrator':
            actions_list.append(f'<button class="btn-action btn-delete" onclick="confirmDelete({file.id}, \'{file.original_filename}\')">🗑️ Delete</button>')
        
        actions = '<div style="display: flex; flex-wrap: wrap; gap: 4px; align-items: center;">' + ''.join(actions_list) + '</div>'
        
        file_rows += f'''
        <tr>
            <td>{file.original_filename}</td>
            <td>{file.uploaded_at.strftime('%Y-%m-%d %H:%M')}</td>
            <td>{file_size_mb:.2f} MB</td>
            <td>{file.uploader.username}</td>
            <td><span class="status-{status_class}">{status_display}</span></td>
            <td>{events_display}</td>
            <td>{violations_display}</td>
            <td>{iocs_display}</td>
            <td>{actions}</td>
        </tr>
        '''
    
    if not file_rows:
        file_rows = '<tr><td colspan="9" style="text-align: center; padding: 40px;">No files uploaded yet. Click "Upload Files" to add files to this case.</td></tr>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Files - {case.name} - caseScope 7.1</title>
        {get_theme_css()}    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            {render_sidebar_menu('files')}
        </div>
        <div class="main-content">
            <div class="header">
                <div class="case-title">📁 {case.name}</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                <h1>📄 Case Files</h1>
                <p>Files uploaded to: {case.name}</p>
                
                {flash_messages_html}
                
                <!-- Real-time Statistics Tiles -->
                <div class="stats-tiles" style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-bottom: 30px;">
                    <!-- Tile 1: File Status Breakdown -->
                    <div class="stat-tile" style="background: linear-gradient(145deg, #1e293b, #334155); padding: 20px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.3);">
                        <h3 style="margin: 0 0 15px 0; color: #f1f5f9; font-size: 1.1em;">📊 File Status</h3>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;">
                            <div class="stat-item">
                                <div class="stat-label" style="color: #94a3b8; font-size: 0.85em;">Completed</div>
                                <div id="stat-completed" class="stat-value" style="color: #4caf50; font-size: 1.8em; font-weight: 700;">-</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-label" style="color: #94a3b8; font-size: 0.85em;">Queued</div>
                                <div id="stat-queued" class="stat-value" style="color: #9ca3af; font-size: 1.8em; font-weight: 700;">-</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-label" style="color: #94a3b8; font-size: 0.85em;">Indexing</div>
                                <div id="stat-indexing" class="stat-value" style="color: #ff9800; font-size: 1.8em; font-weight: 700;">-</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-label" style="color: #94a3b8; font-size: 0.85em;">SIGMA Hunting</div>
                                <div id="stat-sigma" class="stat-value" style="color: #fbbf24; font-size: 1.8em; font-weight: 700;">-</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-label" style="color: #94a3b8; font-size: 0.85em;">IOC Hunting</div>
                                <div id="stat-ioc-hunting" class="stat-value" style="color: #60a5fa; font-size: 1.8em; font-weight: 700;">-</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-label" style="color: #94a3b8; font-size: 0.85em;">Failed</div>
                                <div id="stat-failed" class="stat-value" style="color: #f44336; font-size: 1.8em; font-weight: 700;">-</div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Tile 2: Overall Metrics -->
                    <div class="stat-tile" style="background: linear-gradient(145deg, #1e293b, #334155); padding: 20px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.3);">
                        <h3 style="margin: 0 0 15px 0; color: #f1f5f9; font-size: 1.1em;">📈 Overall Metrics</h3>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;">
                            <div class="stat-item">
                                <div class="stat-label" style="color: #94a3b8; font-size: 0.85em;">Total Files</div>
                                <div id="stat-total-files" class="stat-value" style="color: #3b82f6; font-size: 1.8em; font-weight: 700;">-</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-label" style="color: #94a3b8; font-size: 0.85em;">Total Events</div>
                                <div id="stat-total-events" class="stat-value" style="color: #10b981; font-size: 1.8em; font-weight: 700;">-</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-label" style="color: #94a3b8; font-size: 0.85em;">SIGMA Violations</div>
                                <div id="stat-total-violations" class="stat-value" style="color: #ef4444; font-size: 1.8em; font-weight: 700;">-</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-label" style="color: #94a3b8; font-size: 0.85em;">Events with IOCs</div>
                                <div id="stat-events-iocs" class="stat-value" style="color: #f59e0b; font-size: 1.8em; font-weight: 700;">-</div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div style="margin: 20px 0; display: flex; gap: 15px; align-items: center;">
                    <a href="/upload" class="btn">📤 Upload Files</a>
                    <button onclick="reindexAllFilesBulk()" class="btn" style="background: linear-gradient(145deg, #2196f3, #1976d2);">🔄 Re-index All Files</button>
                    <button onclick="rerunAllRulesBulk()" class="btn" style="background: linear-gradient(145deg, #ff9800, #f57c00);">⚡ Re-run All Rules</button>
                    <button onclick="rehuntAllIocsBulk()" class="btn" style="background: linear-gradient(145deg, #10b981, #059669);">🎯 Re-hunt All IOCs</button>
                </div>
                
                <table class="file-table">
                    <thead>
                        <tr>
                            <th>Filename</th>
                            <th>Uploaded</th>
                            <th>Size</th>
                            <th>Uploaded By</th>
                            <th>Status</th>
                            <th>Events</th>
                            <th>Violations</th>
                            <th>IOCs</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {file_rows}
                    </tbody>
                </table>
            </div>
        </div>
        
        <script>
            function showFileDetails(fileId) {{
                alert('File details view coming soon. File ID: ' + fileId);
                // TODO: Open modal with full file details including hash, metadata, etc.
            }}
            
            function confirmReindex(fileId) {{
                if (confirm('Re-index this file? This will discard all existing event records and re-parse the file.')) {{
                    var form = document.createElement('form');
                    form.method = 'POST';
                    form.action = '/file/reindex/' + fileId;
                    document.body.appendChild(form);
                    form.submit();
                }}
            }}
            
            function confirmRerunRules(fileId) {{
                if (confirm('Re-run SIGMA rules on this file? This will discard existing rule tags and re-scan all events.')) {{
                    var form = document.createElement('form');
                    form.method = 'POST';
                    form.action = '/file/rerun-rules/' + fileId;
                    document.body.appendChild(form);
                    form.submit();
                }}
            }}
            
            function confirmRehuntIocs(fileId) {{
                if (confirm('Re-hunt IOCs on this file? This will discard existing IOC matches and re-scan all events for current IOCs.')) {{
                    var form = document.createElement('form');
                    form.method = 'POST';
                    form.action = '/file/rehunt-iocs/' + fileId;
                    document.body.appendChild(form);
                    form.submit();
                }}
            }}
            
            function confirmDelete(fileId, filename) {{
                if (confirm('DELETE file "' + filename + '"? This will remove the file, all indexed events, and rule violations. This cannot be undone.')) {{
                    if (confirm('Are you ABSOLUTELY SURE? This is permanent!')) {{
                        alert('File deletion not yet implemented. File ID: ' + fileId);
                        // TODO: POST to /files/delete/<fileId>
                    }}
                }}
            }}
            
            // Real-time progress tracking
            const activeFiles = [];
            
            // Collect all file IDs that are being processed
            document.addEventListener('DOMContentLoaded', function() {{
                // Find all progress containers with data-file-id attribute
                const progressContainers = document.querySelectorAll('.progress-container[data-file-id]');
                progressContainers.forEach(function(elem) {{
                    const fileId = elem.getAttribute('data-file-id');
                    if (fileId && !activeFiles.includes(fileId)) {{
                        activeFiles.push(fileId);
                    }}
                }});
                
                // Check for active processing statuses
                const statusElements = document.querySelectorAll('[id^="status-"]');
                statusElements.forEach(function(elem) {{
                    const fileId = elem.id.split('-')[1];
                    const statusText = elem.textContent;
                    if ((statusText.includes('Queued') || 
                         statusText.includes('Estimating') || 
                         statusText.includes('Indexing') ||
                         statusText.includes('SIGMA Hunting') ||
                         statusText.includes('IOC Hunting')) && 
                        !activeFiles.includes(fileId)) {{
                        activeFiles.push(fileId);
                    }}
                }});
                
                // Start polling for active files
                if (activeFiles.length > 0) {{
                    console.log('Starting progress tracking for files:', activeFiles);
                    updateFileProgress();
                    setInterval(updateFileProgress, 2000); // Update every 2 seconds
                }}
                
                // Note: Removed auto-refresh to prevent scroll-to-top
                // Progress updates via AJAX are sufficient
            }});
            
            function updateFileProgress() {{
                activeFiles.forEach(function(fileId) {{
                    fetch('/api/file/progress/' + fileId)
                        .then(response => response.json())
                        .then(data => {{
                            const progressBar = document.getElementById('progress-' + fileId);
                            const eventsText = document.getElementById('events-' + fileId);
                            const statusElem = document.getElementById('status-' + fileId);
                            
                            console.log('Progress update for file', fileId, ':', data);
                            
                            // Update event count in table
                            const eventCountElem = document.getElementById('event-count-' + fileId);
                            if (eventCountElem && data.event_count > 0) {{
                                eventCountElem.textContent = data.event_count.toLocaleString();
                            }}
                            
                            // Update violation count in table
                            const violationCountElem = document.getElementById('violation-count-' + fileId);
                            if (violationCountElem && data.violation_count > 0) {{
                                violationCountElem.textContent = data.violation_count.toLocaleString();
                            }}
                            
                            if (data.status === 'Queued') {{
                                // Show queued status
                                if (statusElem) {{
                                    statusElem.innerHTML = '<div style="font-weight: 600; color: #9ca3af;">Queued</div>';
                                }}
                            }} else if (data.status === 'Estimating') {{
                                // Show estimating status
                                if (statusElem) {{
                                    statusElem.innerHTML = '<div style="font-weight: 600; color: #9ca3af;">Estimating...</div>';
                                }}
                            }} else if (data.status === 'Indexing') {{
                                // Update count text (no progress bar) with color
                                    const currentEvents = data.event_count.toLocaleString();
                                    const totalEvents = data.estimated_event_count.toLocaleString();
                                
                                if (eventsText) {{
                                    eventsText.textContent = currentEvents + ' / ' + totalEvents + ' events';
                                }}
                                if (statusElem) {{
                                    statusElem.innerHTML = '<div style="font-weight: 600; color: #ff9800;">Indexing...</div>' +
                                                          '<div style="font-size: 0.9em; color: rgba(255,255,255,0.8); margin-top: 4px;">' + 
                                                          currentEvents + ' / ' + totalEvents + ' events</div>';
                                }}
                            }} else if (data.status === 'SIGMA Hunting') {{
                                // Show SIGMA progress
                                if (statusElem) {{
                                    if (data.event_count) {{
                                        statusElem.innerHTML = '<div style="font-weight: 600; color: #fbbf24;">SIGMA Hunting...</div>' +
                                                              '<div style="font-size: 0.9em; color: rgba(255,255,255,0.8); margin-top: 4px;">Scanning ' +
                                                              data.event_count.toLocaleString() + ' events</div>';
                                    }} else {{
                                        statusElem.innerHTML = '<div style="font-weight: 600; color: #fbbf24;">SIGMA Hunting...</div>';
                                    }}
                                }}
                            }} else if (data.status === 'IOC Hunting') {{
                                // Show IOC hunting progress
                                if (statusElem) {{
                                    statusElem.innerHTML = '<div style="font-weight: 600; color: #60a5fa;">IOC Hunting...</div>';
                                }}
                            }} else if (data.status === 'Completed' || data.status === 'Failed') {{
                                // Update status in-place instead of reloading with color coding
                                if (statusElem) {{
                                    if (data.status === 'Completed') {{
                                        statusElem.innerHTML = '<div style="font-weight: 600; color: #4caf50;">Completed</div>';
                                    }} else {{
                                        statusElem.innerHTML = '<div style="font-weight: 600; color: #f44336;">Failed</div>';
                                    }}
                                }}
                                // Remove from active files list
                                const index = activeFiles.indexOf(fileId);
                                if (index > -1) {{
                                    activeFiles.splice(index, 1);
                                }}
                            }}
                        }})
                        .catch(err => console.error('Error fetching progress:', err));
                }});
            }}
            
            function reindexAllFilesBulk() {{
                if (!confirm('This will re-index ALL files in this case. Existing events will be removed and re-created. This may take several minutes. Continue?')) {{
                    return;
                }}
                
                fetch('/api/reindex-all-files', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{ case_id: {case.id} }})
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        alert('Successfully queued ' + data.files_queued + ' file(s) for re-indexing.');
                        location.reload();
                    }} else {{
                        alert('Error: ' + (data.message || 'Failed to queue files for re-indexing'));
                    }}
                }})
                .catch(error => {{
                    alert('Error: ' + error.message);
                }});
            }}
            
            function rerunAllRulesBulk() {{
                if (!confirm('This will re-run SIGMA rules on ALL indexed files in this case. This may take several minutes. Continue?')) {{
                    return;
                }}
                
                fetch('/api/rerun-all-rules', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{ case_id: {case.id} }})
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        alert('Successfully queued ' + data.files_queued + ' file(s) for SIGMA rule processing.');
                        location.reload();
                    }} else {{
                        alert('Error: ' + (data.message || 'Failed to queue files for processing'));
                    }}
                }})
                .catch(error => {{
                    alert('Error: ' + error.message);
                }});
            }}
            
            function rehuntAllIocsBulk() {{
                if (!confirm('This will re-hunt IOCs on ALL indexed files in this case. Existing IOC matches will be cleared and re-scanned. Continue?')) {{
                    return;
                }}
                
                fetch('/api/rehunt-all-iocs', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{ case_id: {case.id} }})
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        let message = data.message;
                        if (data.files_skipped > 0 && data.skipped_details) {{
                            message += '\\n\\nSkipped files:\\n' + data.skipped_details.join('\\n');
                        }}
                        alert(message);
                        location.reload();
                    }} else {{
                        alert('Error: ' + (data.message || 'Failed to queue files for IOC hunting'));
                    }}
                }})
                .catch(error => {{
                    alert('Error: ' + error.message);
                }});
            }}
            
            // Real-time Case Statistics Update (every 5 seconds)
            function updateCaseStats() {{
                fetch('/api/case/stats/{case.id}')
                    .then(response => response.json())
                    .then(data => {{
                        // Update status counts
                        document.getElementById('stat-completed').textContent = data.status_counts.completed.toLocaleString();
                        document.getElementById('stat-queued').textContent = data.status_counts.queued.toLocaleString();
                        document.getElementById('stat-indexing').textContent = data.status_counts.indexing.toLocaleString();
                        document.getElementById('stat-sigma').textContent = data.status_counts.sigma_hunting.toLocaleString();
                        document.getElementById('stat-ioc-hunting').textContent = data.status_counts.ioc_hunting.toLocaleString();
                        document.getElementById('stat-failed').textContent = data.status_counts.failed.toLocaleString();
                        
                        // Update overall metrics
                        document.getElementById('stat-total-files').textContent = data.totals.total_files.toLocaleString();
                        document.getElementById('stat-total-events').textContent = data.totals.total_events.toLocaleString();
                        document.getElementById('stat-total-violations').textContent = data.totals.total_violations.toLocaleString();
                        document.getElementById('stat-events-iocs').textContent = data.totals.events_with_iocs.toLocaleString();
                    }})
                    .catch(error => {{
                        console.error('Error updating case stats:', error);
                    }});
            }}
            
            // Update stats immediately on page load
            document.addEventListener('DOMContentLoaded', function() {{
                updateCaseStats();
                // Update every 5 seconds
                setInterval(updateCaseStats, 5000);
            }});
        </script>
    </body>
    </html>
    '''

def render_system_settings(settings):
    """Render system settings page with user-friendly DFIR-IRIS configuration"""
    from flask import get_flashed_messages
    import html
    
    # Flash messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    # Checkbox states (get_setting returns boolean True/False, not string 'true'/'false')
    iris_enabled_checked = 'checked' if settings['iris_enabled'] else ''
    iris_auto_sync_checked = 'checked' if settings['iris_auto_sync'] else ''
    
    # Escape values (convert to string first in case of integers/booleans)
    iris_url_safe = html.escape(str(settings['iris_url']), quote=True)
    iris_api_key_safe = html.escape(str(settings['iris_api_key']), quote=True)
    iris_customer_id_safe = html.escape(str(settings['iris_customer_id']), quote=True)
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>System Settings - caseScope {APP_VERSION}</title>
        {get_theme_css()}
        <style>
            .settings-container {{
                max-width: 900px;
                margin: 0 auto;
            }}
            .settings-section {{
                background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 2rem;
                margin-bottom: 2rem;
            }}
            .settings-section h2 {{
                color: #60a5fa;
                font-size: 1.5rem;
                margin: 0 0 0.5rem 0;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            .settings-section .description {{
                color: #94a3b8;
                font-size: 0.95rem;
                margin-bottom: 1.5rem;
                line-height: 1.6;
            }}
            .form-group {{
                margin-bottom: 1.5rem;
            }}
            .form-group label {{
                display: block;
                color: #e2e8f0;
                font-weight: 600;
                margin-bottom: 0.5rem;
                font-size: 0.95rem;
            }}
            .form-group .help-text {{
                display: block;
                color: #94a3b8;
                font-size: 0.85rem;
                margin-top: 0.3rem;
                line-height: 1.4;
            }}
            .form-group input[type="text"],
            .form-group input[type="password"],
            .form-group input[type="number"] {{
                width: 100%;
                padding: 0.75rem;
                background: #0f172a;
                border: 1px solid #334155;
                border-radius: 6px;
                color: white;
                font-size: 0.95rem;
                font-family: 'Courier New', monospace;
            }}
            .form-group input[type="text"]:focus,
            .form-group input[type="password"]:focus,
            .form-group input[type="number"]:focus {{
                outline: none;
                border-color: #60a5fa;
                box-shadow: 0 0 0 2px rgba(96, 165, 250, 0.1);
            }}
            .checkbox-group {{
                display: flex;
                align-items: center;
                gap: 10px;
                padding: 1rem;
                background: #0f172a;
                border: 1px solid #334155;
                border-radius: 6px;
                cursor: pointer;
                transition: all 0.2s;
            }}
            .checkbox-group:hover {{
                border-color: #60a5fa;
                background: #1e293b;
            }}
            .checkbox-group input[type="checkbox"] {{
                width: 20px;
                height: 20px;
                cursor: pointer;
            }}
            .checkbox-group label {{
                flex: 1;
                margin: 0 !important;
                cursor: pointer;
                color: #e2e8f0;
            }}
            .checkbox-group .help-text {{
                display: block;
                color: #94a3b8;
                font-size: 0.85rem;
                font-weight: normal;
                margin-top: 0.3rem;
            }}
            .button-group {{
                display: flex;
                gap: 1rem;
                margin-top: 2rem;
            }}
            .btn-save {{
                background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                color: white;
                padding: 0.75rem 2rem;
                border: none;
                border-radius: 6px;
                font-size: 1rem;
                font-weight: bold;
                cursor: pointer;
                transition: all 0.2s;
            }}
            .btn-save:hover {{
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(16, 185, 129, 0.4);
            }}
            .btn-test {{
                background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
                color: white;
                padding: 0.75rem 2rem;
                border: none;
                border-radius: 6px;
                font-size: 1rem;
                font-weight: bold;
                cursor: pointer;
                transition: all 0.2s;
            }}
            .btn-test:hover {{
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
            }}
            .btn-test:disabled {{
                opacity: 0.5;
                cursor: not-allowed;
            }}
            .test-result {{
                margin-top: 1rem;
                padding: 1rem;
                border-radius: 6px;
                display: none;
            }}
            .test-result.success {{
                background: rgba(16, 185, 129, 0.1);
                border: 1px solid #10b981;
                color: #10b981;
            }}
            .test-result.error {{
                background: rgba(239, 68, 68, 0.1);
                border: 1px solid #ef4444;
                color: #ef4444;
            }}
            .info-box {{
                background: rgba(59, 130, 246, 0.1);
                border: 1px solid #3b82f6;
                border-radius: 8px;
                padding: 1rem;
                margin-bottom: 1.5rem;
            }}
            .info-box strong {{
                color: #60a5fa;
                display: block;
                margin-bottom: 0.5rem;
            }}
            .info-box ul {{
                margin: 0.5rem 0 0 1.5rem;
                color: #94a3b8;
                line-height: 1.8;
            }}
            .status-badge {{
                display: inline-block;
                padding: 4px 12px;
                border-radius: 12px;
                font-size: 0.85rem;
                font-weight: bold;
            }}
            .status-enabled {{
                background: rgba(16, 185, 129, 0.2);
                color: #10b981;
            }}
            .status-disabled {{
                background: rgba(148, 163, 184, 0.2);
                color: #94a3b8;
            }}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            {render_sidebar_menu('settings')}
        </div>
        <div class="main-content">
            <div class="header">
                <div class="case-title">⚙️ System Settings</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                {flash_messages_html}
                
                <div class="settings-container">
                    <form method="POST" action="/settings/save" id="settingsForm">
                        <!-- DFIR-IRIS Integration Section -->
                        <div class="settings-section">
                            <h2>
                                🔗 DFIR-IRIS Integration
                                <span class="status-badge status-{'enabled' if settings['iris_enabled'] else 'disabled'}" id="statusBadge">
                                    {'ENABLED' if settings['iris_enabled'] else 'DISABLED'}
                                </span>
                            </h2>
                            <p class="description">
                                Connect caseScope to your DFIR-IRIS incident response platform. This allows you to automatically share cases, indicators of compromise (IOCs), and timeline events with your team.
                            </p>
                            
                            <div class="info-box">
                                <strong>📚 What is DFIR-IRIS?</strong>
                                <p style="color: #94a3b8; margin: 0.5rem 0;">
                                    DFIR-IRIS is an incident response platform that helps teams collaborate on security investigations. 
                                    When enabled, caseScope will send your findings to DFIR-IRIS so everyone on your team can see them.
                                </p>
                                <strong style="margin-top: 1rem;">✅ What gets shared:</strong>
                                <ul>
                                    <li>Case information (name, description, priority)</li>
                                    <li>IOCs you've identified (suspicious IPs, domains, file hashes, etc.)</li>
                                    <li>Events you've tagged for the timeline</li>
                                </ul>
                            </div>
                            
                            <div class="form-group">
                                <input type="hidden" name="iris_enabled" value="false">
                                <div class="checkbox-group" onclick="toggleCheckbox('iris_enabled', event)">
                                    <input type="checkbox" id="iris_enabled" name="iris_enabled" value="true" {iris_enabled_checked} onchange="updateFormState()">
                                    <label for="iris_enabled">
                                        Enable DFIR-IRIS Integration
                                        <span class="help-text">Turn this on to connect to DFIR-IRIS</span>
                                    </label>
                                </div>
                            </div>
                            
                            <div id="irisSettings" style="{'display: block;' if settings['iris_enabled'] else 'display: none;'}">
                                <div class="form-group">
                                    <label for="iris_url">
                                        DFIR-IRIS Server URL
                                    </label>
                                    <input type="text" id="iris_url" name="iris_url" value="{iris_url_safe}" placeholder="https://iris.yourcompany.com">
                                    <span class="help-text">
                                        The web address of your DFIR-IRIS server (ask your IT team if you're not sure)
                                    </span>
                                </div>
                                
                                <div class="form-group">
                                    <label for="iris_api_key">
                                        API Key (Secret Token)
                                    </label>
                                    <input type="password" id="iris_api_key" name="iris_api_key" value="{iris_api_key_safe}" placeholder="Enter your API key">
                                    <span class="help-text">
                                        A secret code that lets caseScope connect to DFIR-IRIS. Get this from your DFIR-IRIS profile settings.
                                    </span>
                                </div>
                                
                                <div class="form-group">
                                    <label for="iris_customer_id">
                                        Customer ID (Organization Number)
                                    </label>
                                    <input type="number" id="iris_customer_id" name="iris_customer_id" value="{iris_customer_id_safe}" placeholder="1">
                                    <span class="help-text">
                                        The organization number in DFIR-IRIS (usually 1, but check with your team)
                                    </span>
                                </div>
                                
                                <div class="form-group">
                                    <input type="hidden" name="iris_auto_sync" value="false">
                                    <div class="checkbox-group" onclick="toggleCheckbox('iris_auto_sync', event)">
                                        <input type="checkbox" id="iris_auto_sync" name="iris_auto_sync" value="true" {iris_auto_sync_checked}>
                                        <label for="iris_auto_sync">
                                            Automatic Sync
                                            <span class="help-text">Automatically send new IOCs and tagged events to DFIR-IRIS (recommended)</span>
                                        </label>
                                    </div>
                                </div>
                                
                                <div class="button-group">
                                    <button type="button" class="btn-test" onclick="testConnection()">
                                        🔍 Test Connection
                                    </button>
                                </div>
                                
                                <div id="testResult" class="test-result"></div>
                            </div>
                        </div>
                        
                        <div class="button-group">
                            <button type="submit" class="btn-save">
                                💾 Save Settings
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <script>
            function toggleCheckbox(id, event) {{
                // Don't toggle if the click was directly on the checkbox or label
                // (they handle it natively)
                if (event.target.tagName === 'INPUT' || event.target.tagName === 'LABEL') {{
                    return;
                }}
                const checkbox = document.getElementById(id);
                checkbox.checked = !checkbox.checked;
                if (id === 'iris_enabled') {{
                    updateFormState();
                }}
            }}
            
            function updateFormState() {{
                const enabled = document.getElementById('iris_enabled').checked;
                const settings = document.getElementById('irisSettings');
                const statusBadge = document.getElementById('statusBadge');
                
                if (enabled) {{
                    settings.style.display = 'block';
                    statusBadge.className = 'status-badge status-enabled';
                    statusBadge.textContent = 'ENABLED';
                }} else {{
                    settings.style.display = 'none';
                    statusBadge.className = 'status-badge status-disabled';
                    statusBadge.textContent = 'DISABLED';
                }}
            }}
            
            // Call updateFormState on page load to set initial state
            updateFormState();
            
            function testConnection() {{
                const resultDiv = document.getElementById('testResult');
                const testBtn = event.target;
                const url = document.getElementById('iris_url').value;
                const apiKey = document.getElementById('iris_api_key').value;
                
                if (!url || !apiKey) {{
                    resultDiv.className = 'test-result error';
                    resultDiv.style.display = 'block';
                    resultDiv.textContent = '⚠️ Please enter both URL and API Key first';
                    return;
                }}
                
                testBtn.disabled = true;
                testBtn.textContent = '⏳ Testing...';
                resultDiv.style.display = 'none';
                
                const formData = new FormData();
                formData.append('iris_url', url);
                formData.append('iris_api_key', apiKey);
                
                fetch('/settings/test-iris', {{
                    method: 'POST',
                    body: formData
                }})
                .then(response => response.json())
                .then(data => {{
                    resultDiv.className = 'test-result ' + (data.success ? 'success' : 'error');
                    resultDiv.style.display = 'block';
                    resultDiv.innerHTML = '<strong>' + data.message + '</strong>';
                    if (data.details) {{
                        resultDiv.innerHTML += '<div style="margin-top: 0.5rem; font-size: 0.85rem;">' + data.details + '</div>';
                    }}
                }})
                .catch(error => {{
                    resultDiv.className = 'test-result error';
                    resultDiv.style.display = 'block';
                    resultDiv.textContent = '❌ Error: ' + error.message;
                }})
                .finally(() => {{
                    testBtn.disabled = false;
                    testBtn.textContent = '🔍 Test Connection';
                }});
            }}
        </script>
    </body>
    </html>
    '''

def render_audit_log(logs_paginated, category_filter, user_filter, success_filter, all_users, page, per_page):
    """Render audit log page"""
    from flask import get_flashed_messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    # Build log rows
    log_rows = ""
    for log in logs_paginated.items:
        status_class = "success" if log.success else "failed"
        status_icon = "✓" if log.success else "✗"
        category_colors = {
            'authentication': '#2196f3',
            'file_operation': '#ff9800',
            'search': '#9c27b0',
            'admin': '#f44336'
        }
        category_color = category_colors.get(log.category, '#666')
        
        log_rows += f'''
        <tr>
            <td>{log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
            <td>{log.username or 'Anonymous'}</td>
            <td>{log.ip_address or 'N/A'}</td>
            <td><span class="role-badge" style="background: {category_color};">{log.category.replace('_', ' ').title()}</span></td>
            <td>{log.action.replace('_', ' ').title()}</td>
            <td>{log.details or ''}</td>
            <td><span class="status-badge status-{status_class}">{status_icon}</span></td>
        </tr>
        '''
    
    if not log_rows:
        log_rows = '<tr><td colspan="7" style="text-align: center; padding: 40px;">No audit logs found</td></tr>'
    
    # Build user filter options
    user_options = '<option value="all">All Users</option>'
    for user in all_users:
        selected = 'selected' if user == user_filter else ''
        user_options += f'<option value="{user}" {selected}>{user}</option>'
    
    # Pagination
    has_prev = logs_paginated.has_prev
    has_next = logs_paginated.has_next
    prev_url = f"/audit-log?category={category_filter}&user={user_filter}&success={success_filter}&page={page-1}" if has_prev else "#"
    next_url = f"/audit-log?category={category_filter}&user={user_filter}&success={success_filter}&page={page+1}" if has_next else "#"
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Audit Log - caseScope 7.3</title>
        {get_theme_css()}    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            {render_sidebar_menu('audit_log')}
        </div>
        <div class="main-content">
            <div class="header">
                <div class="case-title">📜 Audit Log</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                {flash_messages_html}
                
                <div class="filters">
                    <form method="GET">
                        <label style="margin-right: 10px;">Category:</label>
                        <select name="category">
                            <option value="all" {'selected' if category_filter == 'all' else ''}>All Categories</option>
                            <option value="authentication" {'selected' if category_filter == 'authentication' else ''}>Authentication</option>
                            <option value="file_operation" {'selected' if category_filter == 'file_operation' else ''}>File Operations</option>
                            <option value="search" {'selected' if category_filter == 'search' else ''}>Search</option>
                            <option value="admin" {'selected' if category_filter == 'admin' else ''}>Admin</option>
                        </select>
                        
                        <label style="margin-left: 20px; margin-right: 10px;">User:</label>
                        <select name="user">
                            {user_options}
                        </select>
                        
                        <label style="margin-left: 20px; margin-right: 10px;">Status:</label>
                        <select name="success">
                            <option value="all" {'selected' if success_filter == 'all' else ''}>All</option>
                            <option value="success" {'selected' if success_filter == 'success' else ''}>Success</option>
                            <option value="failure" {'selected' if success_filter == 'failure' else ''}>Failure</option>
                        </select>
                        
                        <button type="submit" class="btn" style="margin-left: 20px;">Filter</button>
                    </form>
                </div>
                
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>User</th>
                            <th>IP Address</th>
                            <th>Category</th>
                            <th>Action</th>
                            <th>Details</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {log_rows}
                    </tbody>
                </table>
                
                <div class="pagination">
                    <a href="{prev_url}" class="{'disabled' if not has_prev else ''}">← Previous</a>
                    <span style="color: white; padding: 10px;">Page {page}</span>
                    <a href="{next_url}" class="{'disabled' if not has_next else ''}">Next →</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

def render_user_management(users):
    """Render user management page"""
    from flask import get_flashed_messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    # Build user rows
    user_rows = ""
    for user in users:
        status_class = "active" if user.is_active else "inactive"
        status_text = "Active" if user.is_active else "Inactive"
        role_badge_color = "#4caf50" if user.role == "administrator" else "#2196f3" if user.role == "analyst" else "#ff9800"
        
        user_rows += f'''
        <tr>
            <td>{user.username}</td>
            <td>{user.email}</td>
            <td><span class="role-badge" style="background: {role_badge_color};">{user.role.title()}</span></td>
            <td><span class="status-badge status-{status_class}">{status_text}</span></td>
            <td>{user.created_at.strftime('%Y-%m-%d %H:%M')}</td>
            <td class="actions-cell">
                <button class="btn-action btn-edit" onclick="showEditModal({user.id}, '{user.username}', '{user.email}', '{user.role}', {str(user.is_active).lower()})">✏️ Edit</button>
                <button class="btn-action btn-delete" onclick="confirmDeleteUser({user.id}, '{user.username}')" {'disabled' if user.id == current_user.id else ''}>🗑️ Delete</button>
            </td>
        </tr>
        '''
    
    if not user_rows:
        user_rows = '<tr><td colspan="6" style="text-align: center; padding: 40px;">No users found</td></tr>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>User Management - caseScope 7.2</title>
        {get_theme_css()}    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            {render_sidebar_menu('user_management')}
        </div>
        <div class="main-content">
            <div class="header">
                <div class="case-title">👥 User Management</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                {flash_messages_html}
                
                <button class="btn" onclick="showCreateModal()">➕ Create New User</button>
                
                <table>
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {user_rows}
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Create User Modal -->
        <div id="createModal" class="modal">
            <div class="modal-content">
                <h2>Create New User</h2>
                <form method="POST" action="/users/create">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" name="username" required>
                    </div>
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" name="password" required minlength="8">
                    </div>
                    <div class="form-group">
                        <label>Role</label>
                        <select name="role" required>
                            <option value="read-only">Read Only</option>
                            <option value="analyst">Analyst</option>
                            <option value="administrator">Administrator</option>
                        </select>
                    </div>
                    <div class="modal-buttons">
                        <button type="button" class="btn" onclick="closeModal('createModal')" style="background: #666;">Cancel</button>
                        <button type="submit" class="btn">Create User</button>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- Edit User Modal -->
        <div id="editModal" class="modal">
            <div class="modal-content">
                <h2>Edit User</h2>
                <form method="POST" id="editForm">
                    <input type="hidden" id="edit-user-id">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" id="edit-username" readonly style="background: rgba(255,255,255,0.05);">
                    </div>
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" name="email" id="edit-email" required>
                    </div>
                    <div class="form-group">
                        <label>Role</label>
                        <select name="role" id="edit-role" required>
                            <option value="read-only">Read Only</option>
                            <option value="analyst">Analyst</option>
                            <option value="administrator">Administrator</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Status</label>
                        <select name="is_active" id="edit-active" required>
                            <option value="true">Active</option>
                            <option value="false">Inactive</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>New Password (leave blank to keep current)</label>
                        <input type="password" name="new_password" id="edit-password" minlength="8">
                    </div>
                    <div class="modal-buttons">
                        <button type="button" class="btn" onclick="closeModal('editModal')" style="background: #666;">Cancel</button>
                        <button type="submit" class="btn">Update User</button>
                    </div>
                </form>
            </div>
        </div>
        
        <script>
            function showCreateModal() {{
                document.getElementById('createModal').style.display = 'flex';
            }}
            
            function showEditModal(id, username, email, role, isActive) {{
                document.getElementById('edit-user-id').value = id;
                document.getElementById('edit-username').value = username;
                document.getElementById('edit-email').value = email;
                document.getElementById('edit-role').value = role;
                document.getElementById('edit-active').value = isActive.toString();
                document.getElementById('editForm').action = '/users/edit/' + id;
                document.getElementById('editModal').style.display = 'flex';
            }}
            
            function closeModal(modalId) {{
                document.getElementById(modalId).style.display = 'none';
            }}
            
            function confirmDeleteUser(id, username) {{
                if (confirm('Delete user "' + username + '"? This cannot be undone.')) {{
                    var form = document.createElement('form');
                    form.method = 'POST';
                    form.action = '/users/delete/' + id;
                    document.body.appendChild(form);
                    form.submit();
                }}
            }}
            
            // Close modal when clicking outside
            window.onclick = function(event) {{
                if (event.target.className === 'modal') {{
                    event.target.style.display = 'none';
                }}
            }}
        </script>
    </body>
    </html>
    '''

def render_search_history_sidebar(recent_searches, saved_searches):
    """Render search history and saved searches sidebar"""
    html = '<div class="search-history-sidebar">'
    
    # Recent Searches
    html += '<div class="history-section">'
    html += '<h4 style="margin: 0 0 10px 0; font-size: 14px; color: rgba(255,255,255,0.9);">🕐 Recent Searches</h4>'
    if recent_searches:
        html += '<div class="history-list">'
        for search in recent_searches[:5]:  # Show last 5
            import html as html_lib
            escaped_query = html_lib.escape(search.query)
            html += f'<div class="history-item" onclick="loadSearch(\'{escaped_query}\')" title="Click to run this search again">{escaped_query}</div>'
        html += '</div>'
    else:
        html += '<div style="color: rgba(255,255,255,0.5); font-size: 12px;">No recent searches</div>'
    html += '</div>'
    
    # Saved Searches
    html += '<div class="history-section" style="margin-top: 15px;">'
    html += '<h4 style="margin: 0 0 10px 0; font-size: 14px; color: rgba(255,255,255,0.9);">⭐ Saved Searches</h4>'
    if saved_searches:
        html += '<div class="history-list">'
        for search in saved_searches:
            import html as html_lib
            escaped_query = html_lib.escape(search.query)
            escaped_name = html_lib.escape(search.name)
            html += f'<div class="history-item saved" onclick="loadSearch(\'{escaped_query}\')" title="{escaped_name}">{escaped_name}</div>'
        html += '</div>'
    else:
        html += '<div style="color: rgba(255,255,255,0.5); font-size: 12px;">No saved searches</div>'
    html += '</div>'
    
    html += '</div>'
    return html

def render_wazuh_style_fields(data, path=""):
    """
    Render event data in Wazuh-style field table with filter actions
    Each field has buttons to filter for/against the value
    """
    import html as html_lib
    
    html = '<table class="field-table">'
    
    if isinstance(data, dict):
        for key, value in sorted(data.items()):
            current_path = f"{path}.{key}" if path else key
            
            # Skip internal metadata for cleaner view
            if key == '_casescope_metadata':
                continue
            
            if isinstance(value, dict):
                # Nested object - render as collapsible section with nested table
                html += f'''
                <tr class="field-group-row">
                    <td colspan="2" class="field-group-header" onclick="toggleFieldGroup(this)">
                        <span class="expand-icon">▶</span> {html_lib.escape(key)}
                    </td>
                </tr>
                <tr class="field-group-content" style="display: none;">
                    <td colspan="2" style="padding-left: 30px;">
                        {render_wazuh_style_fields(value, current_path)}
                    </td>
                </tr>
                '''
            elif isinstance(value, list):
                # Array - show as comma-separated if simple types, or nested if complex
                if value and isinstance(value[0], (dict, list)):
                    html += f'''
                    <tr class="field-group-row">
                        <td colspan="2" class="field-group-header" onclick="toggleFieldGroup(this)">
                            <span class="expand-icon">▶</span> {html_lib.escape(key)} <span class="field-meta">({len(value)} items)</span>
                        </td>
                    </tr>
                    <tr class="field-group-content" style="display: none;">
                        <td colspan="2" style="padding-left: 30px;">
                    '''
                    for idx, item in enumerate(value):
                        html += f'<div style="margin-bottom: 10px;"><strong>[{idx}]</strong></div>'
                        html += render_wazuh_style_fields(item, f"{current_path}[{idx}]")
                    html += '</td></tr>'
                else:
                    # Simple array - show as text
                    array_text = ', '.join([html_lib.escape(str(item)) for item in value[:10]])
                    if len(value) > 10:
                        array_text += f' ... ({len(value)} total)'
                    
                    # JavaScript-safe escaping BEFORE HTML escaping
                    first_val = str(value[0]) if value else ''
                    js_safe_path = current_path.replace('\\', '\\\\').replace("'", "\\'")
                    js_safe_value = first_val.replace('\\', '\\\\').replace("'", "\\'").replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
                    
                    html += f'''
                    <tr class="field-row">
                        <td class="field-name">{html_lib.escape(key)}</td>
                        <td class="field-value-cell">
                            <div class="field-value-wrapper">
                                <span class="field-value">{array_text}</span>
                                <div class="field-actions">
                                    <button class="field-action-btn filter-for" onclick="filterFor('{js_safe_path}', '{js_safe_value}')" title="Filter for this value">
                                        <span class="action-icon">+</span>
                                    </button>
                                    <button class="field-action-btn filter-out" onclick="filterOut('{js_safe_path}', '{js_safe_value}')" title="Exclude this value">
                                        <span class="action-icon">−</span>
                                    </button>
                                </div>
                            </div>
                        </td>
                    </tr>
                    '''
            else:
                # Leaf value - render as table row with action buttons
                # FIRST: escape for JavaScript (before HTML escaping which adds &quot; entities)
                str_value = str(value)
                str_path = current_path
                # Escape backslashes first, then single quotes for JavaScript strings
                js_safe_value = str_value.replace('\\', '\\\\').replace("'", "\\'").replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
                js_safe_path = str_path.replace('\\', '\\\\').replace("'", "\\'")
                
                # THEN: escape for HTML display
                escaped_value = html_lib.escape(str_value)
                escaped_key = html_lib.escape(key)
                
                html += f'''
                <tr class="field-row">
                    <td class="field-name">{escaped_key}</td>
                    <td class="field-value-cell">
                        <div class="field-value-wrapper">
                            <span class="field-value">{escaped_value}</span>
                            <div class="field-actions">
                                <button class="field-action-btn filter-for" onclick="filterFor('{js_safe_path}', '{js_safe_value}')" title="Filter for this value">
                                    <span class="action-icon">+</span>
                                </button>
                                <button class="field-action-btn filter-out" onclick="filterOut('{js_safe_path}', '{js_safe_value}')" title="Exclude this value">
                                    <span class="action-icon">−</span>
                                </button>
                                <button class="field-action-btn copy-value" onclick="copyToClipboard('{js_safe_value}')" title="Copy value">
                                    <span class="action-icon">📋</span>
                                </button>
                                <button class="field-action-btn add-ioc" onclick="showIocModal('{js_safe_value}', '{js_safe_path}')" title="Add as IOC" style="background: linear-gradient(145deg, #22c55e, #16a34a); color: white;">
                                    <span class="action-icon">🎯</span>
                                </button>
                            </div>
                        </div>
                    </td>
                </tr>
                '''
    
    html += '</table>'
    return html

def render_search_page(case, query_str, results, total_hits, page, per_page, error_message, indexed_file_count, threat_filter='none', time_range='all', custom_start=None, custom_end=None, recent_searches=[], saved_searches=[], sort_field='relevance', sort_order='desc'):
    """Render search interface with results"""
    from flask import get_flashed_messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    # Build result rows
    result_rows = ""
    if results:
        for idx, result in enumerate(results):
            result_id = f"result-{idx}"
            # Escape single quotes in JSON for JavaScript
            import json
            full_data_json = json.dumps(result['full_data']).replace("'", "\\'")
            
            # Escape HTML entities to prevent rendering errors
            import html
            escaped_source_file = html.escape(result['source_file'], quote=True)
            escaped_computer = html.escape(result['computer'], quote=True)
            escaped_event_type = html.escape(result['event_type'], quote=True)
            
            # Get document ID from result for tagging
            doc_id = result.get('doc_id', '')
            escaped_doc_id = html.escape(doc_id, quote=True)
            
            # Get IOC matches for this event (clickable)
            ioc_badges = ''
            if result.get('ioc_matches'):
                ioc_list = []
                for ioc_match in result['ioc_matches']:
                    ioc_type = ioc_match.get('type', 'unknown')
                    ioc_value = ioc_match.get('value', '')
                    ioc_value_display = ioc_value[:20]
                    ioc_value_escaped = html.escape(ioc_value, quote=True)
                    ioc_list.append(f'<a href="/search?ioc={ioc_value_escaped}" style="background: #fbbf24; color: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 4px; text-decoration: none; cursor: pointer; display: inline-block;" title="Click to search for: {ioc_value_escaped}" onclick="event.stopPropagation();">{ioc_type.upper()}</a>')
                ioc_badges = ''.join(ioc_list)
            
            if not ioc_badges:
                ioc_badges = '<span style="color: #64748b;">-</span>'
            
            result_rows += f'''
            <tr class="result-row">
                <td onclick="toggleDetails('{result_id}')">{result['event_id']}</td>
                <td onclick="toggleDetails('{result_id}')">{result['timestamp'][:19] if result['timestamp'] != 'N/A' else 'N/A'}</td>
                <td onclick="toggleDetails('{result_id}')">{escaped_event_type}</td>
                <td onclick="toggleDetails('{result_id}')"><span class="field-tag" onclick="addToQuery(event, 'source_filename', '{escaped_source_file}')">{escaped_source_file}</span></td>
                <td onclick="toggleDetails('{result_id}')"><span class="field-tag" onclick="addToQuery(event, 'Computer', '{escaped_computer}')">{escaped_computer}</span></td>
                <td onclick="toggleDetails('{result_id}')" style="padding: 8px;">{ioc_badges}</td>
                <td style="text-align: center;">
                    <button class="tag-btn" data-event-id="{escaped_doc_id}" data-timestamp="{result['timestamp']}" onclick="event.stopPropagation(); toggleTag(this);" title="Tag for timeline">
                        <span class="tag-icon">☆</span>
                    </button>
                </td>
            </tr>
            <tr id="{result_id}" class="details-row" style="display: none;">
                <td colspan="7">
                    <div class="event-details">
                        <div class="event-details-header">
                            <h4>Event Fields</h4>
                            <div class="event-details-help">
                                <span class="help-icon" title="Click + to include field in search, − to exclude, 📋 to copy">ℹ️</span>
                                <span class="help-text">Use + to filter for values, − to exclude them</span>
                            </div>
                        </div>
                        {render_wazuh_style_fields(result['full_data'])}
                    </div>
                </td>
            </tr>
            '''
    elif query_str and not error_message:
        result_rows = '<tr><td colspan="7" style="text-align: center; padding: 40px; color: #aaa;">No results found for your query.</td></tr>'
    elif not query_str:
        result_rows = '<tr><td colspan="7" style="text-align: center; padding: 40px; color: #aaa;">Enter a search query above to search indexed events.</td></tr>'
    
    if error_message:
        result_rows = f'<tr><td colspan="7" style="text-align: center; padding: 40px; color: #f44336;"><strong>Error:</strong> {error_message}</td></tr>'
    
    # Pagination
    total_pages = (total_hits + per_page - 1) // per_page if total_hits > 0 else 1
    
    # OpenSearch limits results to 10,000 by default
    opensearch_limit = 10000
    is_limited = total_hits >= opensearch_limit
    max_accessible_page = min(total_pages, opensearch_limit // per_page)
    
    pagination_html = ""
    if total_hits > per_page:
        pagination_html = '<div class="pagination">'
        if page > 1:
            pagination_html += f'<button class="page-btn" onclick="searchPage({page - 1})">← Previous</button>'
        
        # Show warning if results exceed OpenSearch limit
        if is_limited:
            pagination_html += f'<span class="page-info" style="color: #fbbf24;">⚠️ Page {page} of {max_accessible_page} ({total_hits:,}+ results - OpenSearch limits to first {opensearch_limit:,})</span>'
        else:
            pagination_html += f'<span class="page-info">Page {page} of {total_pages} ({total_hits:,} results)</span>'
        
        if page < max_accessible_page:
            pagination_html += f'<button class="page-btn" onclick="searchPage({page + 1})">Next →</button>'
        pagination_html += '</div>'
    elif total_hits > 0:
        pagination_html = f'<div class="pagination"><span class="page-info">{total_hits:,} result{"s" if total_hits != 1 else ""} found</span></div>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search Events - {case.name} - caseScope 7.1</title>
        {get_theme_css()}    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            {render_sidebar_menu('search')}
        </div>
        <div class="main-content">
            <div class="header">
                <div class="case-title">🔍 Search Events - {case.name}</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                <h1>🔍 Search Events</h1>
                
                {flash_messages_html}
                
                <div class="stats-bar">
                    <strong>📊 Searching across {indexed_file_count} indexed file{"s" if indexed_file_count != 1 else ""}</strong> in this case
                </div>
                
                {render_search_history_sidebar(recent_searches, saved_searches)}
                
                <div class="search-box">
                    <form method="POST" id="searchForm">
                        <input type="text" name="query" class="search-input" placeholder="Enter search query (e.g., EventID:4624 AND Computer:SERVER01)" value="{query_str}" autofocus>
                        <input type="hidden" name="page" id="pageInput" value="{page}">
                        <input type="hidden" name="sort" id="sortInput" value="{sort_field}">
                        <input type="hidden" name="sort_order" id="sortOrderInput" value="{sort_order}">
                        
                        <div style="display: flex; gap: 15px; margin-bottom: 15px; align-items: center; flex-wrap: wrap;">
                            <label style="color: rgba(255,255,255,0.9); font-size: 14px;">
                                ⏰ Time Range:
                                <select name="time_range" id="timeRange" onchange="toggleCustomDates()" style="margin-left: 8px; padding: 8px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white;">
                                    <option value="all" {'selected' if time_range == 'all' else ''}>All Time</option>
                                    <option value="24h" {'selected' if time_range == '24h' else ''}>Last 24 Hours</option>
                                    <option value="7d" {'selected' if time_range == '7d' else ''}>Last 7 Days</option>
                                    <option value="30d" {'selected' if time_range == '30d' else ''}>Last 30 Days</option>
                                    <option value="custom" {'selected' if time_range == 'custom' else ''}>Custom Range</option>
                                </select>
                            </label>
                            
                            <div id="customDates" style="display: {'flex' if time_range == 'custom' else 'none'}; gap: 10px; align-items: center;">
                                <input type="datetime-local" name="custom_start" value="{custom_start or ''}" style="padding: 8px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white;">
                                <span style="color: rgba(255,255,255,0.7);">to</span>
                                <input type="datetime-local" name="custom_end" value="{custom_end or ''}" style="padding: 8px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white;">
                            </div>
                        </div>
                        
                        <div class="search-actions">
                            <div style="display: flex; align-items: center; margin-right: 15px;">
                                <label style="color: rgba(255,255,255,0.9); margin-right: 8px; font-size: 14px; font-weight: 500;">🎯 Threat Filtering:</label>
                                <select name="threat_filter" style="padding: 6px 12px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white; font-size: 14px; cursor: pointer;">
                                    <option value="none" {'selected' if threat_filter == 'none' else ''}>None (All Events)</option>
                                    <option value="sigma" {'selected' if threat_filter == 'sigma' else ''}>🚨 SIGMA Only</option>
                                    <option value="ioc" {'selected' if threat_filter == 'ioc' else ''}>🎯 IOC Only</option>
                                    <option value="either" {'selected' if threat_filter == 'either' else ''}>⚡ SIGMA or IOC</option>
                                    <option value="both" {'selected' if threat_filter == 'both' else ''}>🔥 SIGMA + IOC (Both)</option>
                                </select>
                            </div>
                            <button type="submit" class="btn-search">🔍 Search</button>
                            <button type="button" class="btn-export" onclick="exportResults()">📥 Export CSV</button>
                            <button type="button" class="help-toggle" onclick="toggleHelp()">❓ Query Help</button>
                        </div>
                    </form>
                    
                    <div id="helpBox" class="help-box">
                        <h4>📖 Search Query Syntax</h4>
                        <ul>
                            <li><code>*</code> - Show ALL events (paginated)</li>
                            <li><code>keyword</code> - Search for keyword anywhere in event data</li>
                            <li><code>field:value</code> - Search specific field (e.g., <code>EventID:5000</code>)</li>
                            <li><code>"exact phrase"</code> - Match exact phrase</li>
                            <li><code>term1 AND term2</code> - Both terms must exist (default)</li>
                            <li><code>term1 OR term2</code> - Either term can exist</li>
                            <li><code>NOT term</code> - Exclude term</li>
                            <li><code>(term1 OR term2) AND term3</code> - Use parentheses for grouping</li>
                            <li><code>field:*wildcard*</code> - Wildcard search</li>
                        </ul>
                        <h4>💡 Pro Tips</h4>
                        <ul>
                            <li><strong>All event data is searchable!</strong> Every field is indexed as text</li>
                            <li>Search for IPs, usernames, file paths, registry keys, etc.</li>
                            <li>Click any green field tag in results to add it to your query</li>
                            <li>Click a result row to expand and see ALL event details</li>
                        </ul>
                        <h4>🎯 Common Fields (Shortcuts)</h4>
                        <ul>
                            <li><code>EventID</code> - Event identifier (e.g., 4624, 4625, 5000)</li>
                            <li><code>Computer</code> - Computer/hostname</li>
                            <li><code>Channel</code> - Event log channel</li>
                            <li><code>Provider</code> - Event source/provider</li>
                            <li><code>Level</code> - Event level (2=Error, 3=Warning, 4=Info)</li>
                        </ul>
                        <h4>🎯 Example Queries</h4>
                        <ul>
                            <li><code>*</code> - Browse all events</li>
                            <li><code>192.168.1.100</code> - Find events containing this IP</li>
                            <li><code>EventID:4624</code> - Successful logon events</li>
                            <li><code>"C:\\Windows\\System32"</code> - Events with this path</li>
                            <li><code>Administrator AND (EventID:4624 OR EventID:4625)</code> - Admin logons</li>
                            <li><code>Level:2</code> - Only error events</li>
                            <li><code>*.exe</code> - Events mentioning executable files</li>
                        </ul>
                    </div>
                </div>
                
                {pagination_html}
                
                <table class="results-table">
                    <thead>
                        <tr>
                            <th>Event ID</th>
                            <th class="sortable-header">
                                Timestamp 
                                <span class="sort-controls">
                                    <a href="#" onclick="event.preventDefault(); sortBy('timestamp', 'desc')" title="Newest first">▼</a>
                                    <a href="#" onclick="event.preventDefault(); sortBy('timestamp', 'asc')" title="Oldest first">▲</a>
                                </span>
                            </th>
                            <th>Event Information</th>
                            <th>Source File</th>
                            <th>Computer</th>
                            <th>IOCs</th>
                            <th>Tag</th>
                        </tr>
                    </thead>
                    <tbody>
                        {result_rows}
                    </tbody>
                </table>
                
                {pagination_html}
            </div>
        </div>
        
        <script>
            function toggleDetails(rowId) {{
                const detailsRow = document.getElementById(rowId);
                if (detailsRow.style.display === 'none') {{
                    detailsRow.style.display = 'table-row';
                }} else {{
                    detailsRow.style.display = 'none';
                }}
            }}
            
            function toggleHelp() {{
                const helpBox = document.getElementById('helpBox');
                if (helpBox.style.display === 'none' || helpBox.style.display === '') {{
                    helpBox.style.display = 'block';
                }} else {{
                    helpBox.style.display = 'none';
                }}
            }}
            
            function addToQuery(event, field, value) {{
                event.stopPropagation(); // Prevent row click
                const queryInput = document.querySelector('.search-input');
                const currentQuery = queryInput.value.trim();
                const newTerm = field + ':"' + value + '"';
                
                if (currentQuery === '') {{
                    queryInput.value = newTerm;
                }} else {{
                    queryInput.value = currentQuery + ' AND ' + newTerm;
                }}
                queryInput.focus();
            }}
            
            function addFieldToQuery(field, value) {{
                const queryInput = document.querySelector('.search-input');
                const currentQuery = queryInput.value.trim();
                const newTerm = field + ':"' + value + '"';
                
                if (currentQuery === '') {{
                    queryInput.value = newTerm;
                }} else {{
                    queryInput.value = currentQuery + ' AND ' + newTerm;
                }}
                queryInput.focus();
            }}
            
            function loadSearch(query) {{
                const queryInput = document.querySelector('.search-input');
                queryInput.value = query;
                queryInput.focus();
            }}
            
            function filterFor(field, value) {{
                const queryInput = document.querySelector('.search-input');
                const currentQuery = queryInput.value.trim();
                
                // Escape the field name to handle special chars like # in #text
                // Use backslash escaping for OpenSearch query syntax
                const escapedField = field.replace(/([#:])/g, '\\\\$1');
                const newTerm = escapedField + ':"' + value + '"';
                
                if (currentQuery === '' || currentQuery === '*') {{
                    queryInput.value = newTerm;
                }} else {{
                    queryInput.value = currentQuery + ' AND ' + newTerm;
                }}
                
                // Auto-submit the search
                document.getElementById('searchForm').submit();
            }}
            
            function filterOut(field, value) {{
                const queryInput = document.querySelector('.search-input');
                const currentQuery = queryInput.value.trim();
                
                // Escape the field name to handle special chars like # in #text
                const escapedField = field.replace(/([#:])/g, '\\\\$1');
                const newTerm = 'NOT ' + escapedField + ':"' + value + '"';
                
                if (currentQuery === '' || currentQuery === '*') {{
                    queryInput.value = newTerm;
                }} else {{
                    queryInput.value = currentQuery + ' AND ' + newTerm;
                }}
                
                // Auto-submit the search
                document.getElementById('searchForm').submit();
            }}
            
            function copyToClipboard(text) {{
                // Create temporary textarea for copying
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);
                textarea.select();
                
                try {{
                    document.execCommand('copy');
                    // Show brief success message
                    alert('Copied to clipboard: ' + text.substring(0, 50) + (text.length > 50 ? '...' : ''));
                }} catch (err) {{
                    alert('Failed to copy to clipboard');
                }}
                
                document.body.removeChild(textarea);
            }}
            
            function toggleFieldGroup(header) {{
                const groupRow = header.parentElement;
                const contentRow = groupRow.nextElementSibling;
                const icon = header.querySelector('.expand-icon');
                
                if (contentRow && contentRow.classList.contains('field-group-content')) {{
                    if (contentRow.style.display === 'none') {{
                        contentRow.style.display = 'table-row';
                        icon.textContent = '▼';
                    }} else {{
                        contentRow.style.display = 'none';
                        icon.textContent = '▶';
                    }}
                }}
            }}
            
            function searchPage(pageNum) {{
                document.getElementById('pageInput').value = pageNum;
                document.getElementById('searchForm').submit();
            }}
            
            function sortBy(field, order) {{
                document.getElementById('sortInput').value = field;
                document.getElementById('sortOrderInput').value = order;
                document.getElementById('pageInput').value = 1;  // Reset to first page
                document.getElementById('searchForm').submit();
            }}
            
            function exportResults() {{
                const form = document.getElementById('searchForm');
                const originalAction = form.action;
                form.action = '/search/export';
                form.submit();
                form.action = originalAction;
            }}
            
            function toggleCustomDates() {{
                const select = document.getElementById('timeRange');
                const customDiv = document.getElementById('customDates');
                customDiv.style.display = select.value === 'custom' ? 'flex' : 'none';
            }}
            
            // ===== TIMELINE TAGGING FUNCTIONALITY =====
            
            // Store tagged events (loaded from server)
            let taggedEvents = {{}};
            
            // Load tagged events on page load
            function loadTaggedEvents() {{
                fetch('/api/event/tags?tag_type=timeline')
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) {{
                            taggedEvents = data.tagged_events;
                            // Update UI for all tagged events
                            updateTagButtonStates();
                        }}
                    }})
                    .catch(error => {{
                        console.error('Error loading tagged events:', error);
                    }});
            }}
            
            // Update all tag button states based on loaded tags
            function updateTagButtonStates() {{
                document.querySelectorAll('.tag-btn').forEach(btn => {{
                    const eventId = btn.dataset.eventId;
                    const icon = btn.querySelector('.tag-icon');
                    
                    if (taggedEvents[eventId]) {{
                        // Tagged - show filled star
                        icon.textContent = '★';
                        icon.style.color = '#fbbf24';
                        btn.classList.add('tagged');
                        btn.title = 'Remove from timeline (tagged by ' + taggedEvents[eventId][0].tagged_by_username + ')';
                    }} else {{
                        // Not tagged - show empty star
                        icon.textContent = '☆';
                        icon.style.color = '#94a3b8';
                        btn.classList.remove('tagged');
                        btn.title = 'Tag for timeline';
                    }}
                }});
            }}
            
            // Toggle tag on/off for an event
            function toggleTag(button) {{
                const eventId = button.dataset.eventId;
                const timestamp = button.dataset.timestamp;
                const icon = button.querySelector('.tag-icon');
                
                // Determine current state
                const isTagged = button.classList.contains('tagged');
                
                if (isTagged) {{
                    // Untag
                    fetch('/api/event/untag', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{
                            event_id: eventId,
                            tag_type: 'timeline'
                        }})
                    }})
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) {{
                            // Remove from local cache
                            delete taggedEvents[eventId];
                            // Update button
                            icon.textContent = '☆';
                            icon.style.color = '#94a3b8';
                            button.classList.remove('tagged');
                            button.title = 'Tag for timeline';
                        }} else {{
                            alert('Error: ' + data.message);
                        }}
                    }})
                    .catch(error => {{
                        console.error('Error untagging event:', error);
                        alert('Error removing tag: ' + error.message);
                    }});
                }} else {{
                    // Tag
                    // Get current index name from results
                    const indexName = '{case.name.lower().replace(" ", "_")}';  // Simplified for now
                    
                    fetch('/api/event/tag', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{
                            event_id: eventId,
                            index_name: indexName,
                            event_timestamp: timestamp,
                            tag_type: 'timeline',
                            color: 'blue'
                        }})
                    }})
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) {{
                            // Add to local cache
                            taggedEvents[eventId] = [{{
                                tag_id: data.tag_id,
                                tagged_by_username: '{current_user.username}'
                            }}];
                            // Update button
                            icon.textContent = '★';
                            icon.style.color = '#fbbf24';
                            button.classList.add('tagged');
                            button.title = 'Remove from timeline';
                        }} else {{
                            alert('Error: ' + data.message);
                        }}
                    }})
                    .catch(error => {{
                        console.error('Error tagging event:', error);
                        alert('Error tagging event: ' + error.message);
                    }});
                }}
            }}
            
            // Load tagged events when page loads
            document.addEventListener('DOMContentLoaded', loadTaggedEvents);
            
            // IOC Quick-Add Functionality
            function showIocModal(value, fieldPath) {{
                document.getElementById('iocValue').value = value;
                document.getElementById('iocFieldPath').textContent = fieldPath || 'Unknown field';
                
                // Try to auto-detect IOC type from field name
                const suggestedType = detectIocType(fieldPath, value);
                document.getElementById('iocType').value = suggestedType;
                
                document.getElementById('iocQuickAddModal').style.display = 'flex';
            }}
            
            function detectIocType(fieldPath, value) {{
                const path = fieldPath.toLowerCase();
                
                // Pattern-based detection
                if (/^[0-9a-f]{{32}}$/i.test(value)) return 'hash_md5';
                if (/^[0-9a-f]{{40}}$/i.test(value)) return 'hash_sha1';
                if (/^[0-9a-f]{{64}}$/i.test(value)) return 'hash_sha256';
                if (/^(\\d{{1,3}}\\.){{3}}\\d{{1,3}}$/.test(value)) return 'ip';
                if (/@/.test(value)) return 'email';
                
                // Field name-based detection
                if (path.includes('computer') || path.includes('hostname')) return 'hostname';
                if (path.includes('domain')) return 'domain';
                if (path.includes('ip') || path.includes('address')) return 'ip';
                if (path.includes('username') || path.includes('user') || path.includes('account')) return 'username';
                if (path.includes('commandline') || path.includes('command')) return 'command';
                if (path.includes('process') || path.includes('image')) return 'process_name';
                if (path.includes('file') || path.includes('filename')) return 'filename';
                if (path.includes('hash') || path.includes('md5') || path.includes('sha')) {{
                    if (value.length === 32) return 'hash_md5';
                    if (value.length === 40) return 'hash_sha1';
                    if (value.length === 64) return 'hash_sha256';
                }}
                
                return 'command'; // Default fallback
            }}
            
            function closeIocModal() {{
                document.getElementById('iocQuickAddModal').style.display = 'none';
            }}
            
            function submitQuickIoc() {{
                const iocType = document.getElementById('iocType').value;
                const iocValue = document.getElementById('iocValue').value;
                const iocDescription = document.getElementById('iocDescription').value;
                const iocSeverity = document.getElementById('iocSeverity').value;
                
                if (!iocType || !iocValue) {{
                    alert('IOC type and value are required');
                    return;
                }}
                
                // Create form data
                const formData = new FormData();
                formData.append('action', 'add');
                formData.append('ioc_type', iocType);
                formData.append('ioc_value', iocValue);
                formData.append('description', iocDescription);
                formData.append('source', 'Quick Add from Event');
                formData.append('severity', iocSeverity);
                
                // Submit to existing IOC endpoint
                fetch('/ioc/list', {{
                    method: 'POST',
                    body: formData
                }})
                .then(response => {{
                    if (response.ok) {{
                        closeIocModal();
                        alert('✓ IOC added successfully!');
                        // Clear description field for next use
                        document.getElementById('iocDescription').value = '';
                    }} else {{
                        alert('Failed to add IOC. Please try again.');
                    }}
                }})
                .catch(error => {{
                    console.error('Error:', error);
                    alert('Failed to add IOC: ' + error);
                }});
            }}
        </script>
        
        <!-- IOC Quick Add Modal -->
        <div id="iocQuickAddModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 10000; align-items: center; justify-content: center;">
            <div style="background: #1e293b; border-radius: 8px; padding: 30px; max-width: 500px; width: 90%; box-shadow: 0 20px 60px rgba(0,0,0,0.5);">
                <h3 style="margin: 0 0 20px 0; color: #f1f5f9;">🎯 Quick Add IOC</h3>
                
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; color: #cbd5e1; font-weight: 600;">Field Path:</label>
                    <div id="iocFieldPath" style="padding: 8px 12px; background: #0f172a; border-radius: 4px; color: #94a3b8; font-family: monospace; font-size: 0.9em;"></div>
                </div>
                
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; color: #cbd5e1; font-weight: 600;">IOC Type:</label>
                    <select id="iocType" style="width: 100%; padding: 10px; background: #0f172a; color: #f1f5f9; border: 1px solid #334155; border-radius: 4px;">
                        <option value="ip">IP Address</option>
                        <option value="domain">Domain</option>
                        <option value="hostname">Hostname</option>
                        <option value="username">Username</option>
                        <option value="hash_md5">Hash (MD5)</option>
                        <option value="hash_sha1">Hash (SHA1)</option>
                        <option value="hash_sha256">Hash (SHA256)</option>
                        <option value="command">Command/Command Line</option>
                        <option value="filename">Filename</option>
                        <option value="process_name">Process Name</option>
                        <option value="malware_name">Malware Name</option>
                        <option value="registry_key">Registry Key</option>
                        <option value="email">Email Address</option>
                        <option value="url">URL</option>
                    </select>
                </div>
                
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; color: #cbd5e1; font-weight: 600;">IOC Value:</label>
                    <input type="text" id="iocValue" readonly style="width: 100%; padding: 10px; background: #0f172a; color: #f1f5f9; border: 1px solid #334155; border-radius: 4px; font-family: monospace;">
                </div>
                
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; color: #cbd5e1; font-weight: 600;">Description (Optional):</label>
                    <input type="text" id="iocDescription" placeholder="Why is this an IOC?" style="width: 100%; padding: 10px; background: #0f172a; color: #f1f5f9; border: 1px solid #334155; border-radius: 4px;">
                </div>
                
                <div style="margin-bottom: 20px;">
                    <label style="display: block; margin-bottom: 5px; color: #cbd5e1; font-weight: 600;">Severity:</label>
                    <select id="iocSeverity" style="width: 100%; padding: 10px; background: #0f172a; color: #f1f5f9; border: 1px solid #334155; border-radius: 4px;">
                        <option value="low">Low</option>
                        <option value="medium" selected>Medium</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                    </select>
                </div>
                
                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button onclick="closeIocModal()" style="padding: 10px 20px; background: #475569; color: #f1f5f9; border: none; border-radius: 4px; cursor: pointer; font-weight: 600;">Cancel</button>
                    <button onclick="submitQuickIoc()" style="padding: 10px 20px; background: linear-gradient(145deg, #22c55e, #16a34a); color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; box-shadow: 0 4px 12px rgba(34,197,94,0.3);">Add IOC</button>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

def render_sigma_rules_page(all_rules, enabled_count, total_count, total_violations, critical_violations, high_violations):
    """Render SIGMA Rules Management Page"""
    from flask import get_flashed_messages
    
    # Flash messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    # Build rules table
    rules_html = ""
    for rule in all_rules:
        # Parse tags
        try:
            tags = json.loads(rule.tags) if rule.tags else []
            tags_html = ' '.join([f'<span class="tag">{tag}</span>' for tag in tags[:5]])
        except:
            tags_html = ''
        
        # Level badge color
        level_colors = {
            'critical': '#d32f2f',
            'high': '#f44336',
            'medium': '#ff9800',
            'low': '#2196f3',
            'informational': '#4caf50'
        }
        level_color = level_colors.get(rule.level, '#757575')
        
        # Status badge
        status_emoji = '✓' if rule.is_enabled else '✗'
        status_class = 'enabled' if rule.is_enabled else 'disabled'
        
        # Built-in badge
        builtin_badge = '<span class="builtin-badge">🏢 Built-in</span>' if rule.is_builtin else '<span class="user-badge">👤 Custom</span>'
        
        # Violation count for this rule
        rule_violations = db.session.query(SigmaViolation).filter_by(rule_id=rule.id).count()
        
        rules_html += f'''
        <tr class="rule-row" data-rule-id="{rule.id}">
            <td>
                <div class="rule-title">{rule.title}</div>
                <div class="rule-meta">{builtin_badge} {tags_html}</div>
            </td>
            <td><span class="level-badge" style="background: {level_color};">{rule.level.upper()}</span></td>
            <td>{rule.category}</td>
            <td>{rule.author}</td>
            <td>{rule_violations:,}</td>
            <td>
                <span class="status-badge status-{status_class}">{status_emoji} {('Enabled' if rule.is_enabled else 'Disabled')}</span>
            </td>
            <td class="actions-cell">
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="action" value="toggle">
                    <input type="hidden" name="rule_id" value="{rule.id}">
                    <button type="submit" class="btn-action btn-toggle" title="{'Disable' if rule.is_enabled else 'Enable'}">
                        {'⏸' if rule.is_enabled else '▶️'}
                    </button>
                </form>
                <button class="btn-action btn-view" onclick="viewRule({rule.id})" title="View Rule">👁️</button>
                {f'''<form method="POST" style="display: inline;" onsubmit="return confirm('Delete this rule?');">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="rule_id" value="{rule.id}">
                    <button type="submit" class="btn-action btn-delete" title="Delete">🗑️</button>
                </form>''' if not rule.is_builtin else ''}
            </td>
        </tr>
        <tr id="rule-details-{rule.id}" class="rule-details" style="display: none;">
            <td colspan="7">
                <div class="rule-yaml">
                    <h4>Rule YAML</h4>
                    <pre>{rule.rule_yaml}</pre>
                </div>
            </td>
        </tr>
        '''
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIGMA Rules - caseScope 7.1</title>
        {get_theme_css()}    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            {render_sidebar_menu('sigma_rules')}
        </div>
        <div class="main-content">
            <div class="header">
                <div class="case-title">📋 SIGMA Rules Management</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                <h1>📋 SIGMA Rules Management</h1>
                
                {flash_messages_html}
                
                <div class="stats-bar">
                    <div class="stat-item">
                        <div class="stat-value">{total_count}</div>
                        <div class="stat-label">Total Rules</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{enabled_count}</div>
                        <div class="stat-label">Enabled Rules</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{total_violations:,}</div>
                        <div class="stat-label">Total Violations</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{critical_violations + high_violations}</div>
                        <div class="stat-label">Critical/High Violations</div>
                    </div>
                </div>
                
                <div class="upload-box">
                    <h3>📥 Download SigmaHQ Rules</h3>
                    <p>Download 3000+ detection rules from the official SigmaHQ repository on GitHub.</p>
                    <form method="POST" action="/sigma-rules/download">
                        <button type="submit" style="background: linear-gradient(145deg, #2196f3, #1976d2);">Download from GitHub</button>
                    </form>
                </div>
                
                <div class="upload-box">
                    <h3>📤 Upload Custom Rule</h3>
                    <p>Upload YAML files containing SIGMA detection rules. Supports standard SIGMA format.</p>
                    <form method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="action" value="upload">
                        <input type="file" name="rule_file" accept=".yml,.yaml" required>
                        <button type="submit">Upload Rule</button>
                    </form>
                </div>
                
                <div style="margin: 30px 0;">
                    <h3 style="margin-bottom: 15px;">🔍 Search Rules</h3>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <input type="text" id="ruleSearch" placeholder="Search by title, level, or category..." 
                               style="flex: 1; padding: 12px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); 
                                      background: rgba(255,255,255,0.1); color: white; font-size: 14px;"
                               onkeyup="filterRules()">
                        <button onclick="document.getElementById('ruleSearch').value=''; filterRules();" 
                                style="padding: 12px 24px; background: linear-gradient(145deg, #757575, #616161); 
                                       border-radius: 8px; white-space: nowrap; border: none; color: white; cursor: pointer;">Clear</button>
                    </div>
                    <div id="searchStatus" style="margin-top: 10px; font-size: 14px; color: rgba(255,255,255,0.7);"></div>
                </div>
                
                <table class="rules-table">
                    <thead>
                        <tr>
                            <th>Rule</th>
                            <th>Level</th>
                            <th>Category</th>
                            <th>Author</th>
                            <th>Violations</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rules_html if rules_html else '<tr><td colspan="7" style="text-align: center; padding: 40px; color: #aaa;">No SIGMA rules loaded. Upload rules to get started.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
        
        <script>
            function viewRule(ruleId) {{
                const row = document.getElementById('rule-details-' + ruleId);
                if (row.style.display === 'none') {{
                    row.style.display = 'table-row';
                }} else {{
                    row.style.display = 'none';
                }}
            }}
            
            function filterRules() {{
                const searchInput = document.getElementById('ruleSearch').value.toLowerCase();
                const rows = document.querySelectorAll('.rule-row');
                let visibleCount = 0;
                let totalCount = rows.length;
                
                rows.forEach(function(row) {{
                    const title = row.querySelector('.rule-title').textContent.toLowerCase();
                    const level = row.querySelectorAll('.level-badge')[0].textContent.toLowerCase();
                    const category = row.querySelectorAll('td')[2].textContent.toLowerCase();
                    
                    if (title.includes(searchInput) || level.includes(searchInput) || category.includes(searchInput)) {{
                        row.style.display = '';
                        const detailsRow = document.getElementById('rule-details-' + row.dataset.ruleId);
                        if (detailsRow && detailsRow.style.display !== 'none') {{
                            detailsRow.style.display = '';
                        }}
                        visibleCount++;
                    }} else {{
                        row.style.display = 'none';
                        const detailsRow = document.getElementById('rule-details-' + row.dataset.ruleId);
                        if (detailsRow) {{
                            detailsRow.style.display = 'none';
                        }}
                    }}
                }});
                
                const status = document.getElementById('searchStatus');
                if (searchInput) {{
                    status.textContent = `Showing ${{visibleCount}} of ${{totalCount}} rules`;
                }} else {{
                    status.textContent = '';
                }}
            }}
        </script>
    </body>
    </html>
    '''

def render_violations_page(case, violations, total_violations, page, per_page, severity_filter,
                           rule_filter, file_filter, reviewed_filter, all_rules, all_files,
                           total_count, critical_count, high_count, medium_count, low_count, reviewed_count):
    """Render SIGMA Violations Viewer Page"""
    
    # Build violations table
    violations_html = ""
    for v in violations:
        # Parse event data for display
        try:
            event_data = json.loads(v.event_data)
            event_id = event_data.get('System', {}).get('EventID', {}).get('#text', 'N/A')
            computer = event_data.get('System', {}).get('Computer', 'N/A')
            timestamp = event_data.get('System', {}).get('TimeCreated', {}).get('@SystemTime', 'N/A')
        except:
            event_id = 'N/A'
            computer = 'N/A'
            timestamp = 'N/A'
        
        # Severity color
        severity_colors = {
            'critical': '#d32f2f',
            'high': '#f44336',
            'medium': '#ff9800',
            'low': '#2196f3'
        }
        severity_color = severity_colors.get(v.severity, '#757575')
        
        # Review status
        review_badge = '✓ Reviewed' if v.is_reviewed else '⏳ Pending Review'
        review_class = 'reviewed' if v.is_reviewed else 'pending'
        
        violations_html += f'''
        <tr class="violation-row">
            <td><span class="severity-badge" style="background: {severity_color};">{v.severity.upper()}</span></td>
            <td>{v.rule.title}</td>
            <td>{v.file.original_filename}</td>
            <td>{event_id}</td>
            <td>{computer}</td>
            <td>{timestamp[:19] if len(timestamp) > 19 else timestamp}</td>
            <td><span class="review-badge review-{review_class}">{review_badge}</span></td>
            <td class="actions-cell">
                <button class="btn-action btn-view" onclick="viewViolation({v.id})" title="View Details">👁️</button>
                {f'<button class="btn-action btn-review" onclick="showReviewModal({v.id})" title="Mark Reviewed">✓</button>' if not v.is_reviewed else ''}
            </td>
            <td style="text-align: center;">
                <button class="tag-btn" data-event-id="{v.event_id}" data-timestamp="{timestamp}" onclick="event.stopPropagation(); toggleTag(this);" title="Tag for timeline">
                    <span class="tag-icon">☆</span>
                </button>
            </td>
        </tr>
        <tr id="violation-details-{v.id}" class="violation-details" style="display: none;">
            <td colspan="9">
                <div class="violation-detail-panel">
                    <h4>Violation Details</h4>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <strong>Rule:</strong> {v.rule.title}
                            <p style="color: #aaa; font-size: 0.9em;">{v.rule.description}</p>
                        </div>
                        <div class="detail-item">
                            <strong>Severity:</strong> <span style="color: {severity_color};">{v.severity.upper()}</span>
                        </div>
                        <div class="detail-item">
                            <strong>Detected:</strong> {v.detected_at.strftime('%Y-%m-%d %H:%M:%S') if v.detected_at else 'N/A'}
                        </div>
                        {f'<div class="detail-item"><strong>Reviewed By:</strong> {v.reviewer.username if v.reviewer else "N/A"}</div>' if v.is_reviewed else ''}
                        {f'<div class="detail-item"><strong>Review Date:</strong> {v.reviewed_at.strftime("%Y-%m-%d %H:%M:%S") if v.reviewed_at else "N/A"}</div>' if v.is_reviewed else ''}
                        {f'<div class="detail-item" style="grid-column: 1 / -1;"><strong>Notes:</strong><br>{v.notes}</div>' if v.notes else ''}
                    </div>
                    <h4>Event Data 
                        <span style="font-size: 0.8em; color: #94a3b8; font-weight: normal;">
                            (Click <span style="color: #22c55e;">+</span> to add value as IOC)
                        </span>
                    </h4>
                    <div id="event-json-{v.id}" class="event-json-interactive" data-event-json="{html.escape(json.dumps(event_data))}">{json.dumps(event_data, indent=2)}</div>
                </div>
            </td>
        </tr>
        '''
    
    # Build filter dropdowns
    rule_options = ''.join([f'<option value="{r.id}" {"selected" if str(r.id) == rule_filter else ""}>{r.title}</option>' for r in all_rules])
    file_options = ''.join([f'<option value="{f.id}" {"selected" if str(f.id) == file_filter else ""}>{f.original_filename}</option>' for f in all_files])
    
    # Pagination
    total_pages = (total_violations + per_page - 1) // per_page
    pagination_html = ""
    if total_pages > 1:
        if page > 1:
            pagination_html += f'<a href="?page={page-1}&severity={severity_filter}&rule={rule_filter}&file={file_filter}&reviewed={reviewed_filter}" class="page-btn">← Previous</a>'
        pagination_html += f'<span class="page-info">Page {page} of {total_pages}</span>'
        if page < total_pages:
            pagination_html += f'<a href="?page={page+1}&severity={severity_filter}&rule={rule_filter}&file={file_filter}&reviewed={reviewed_filter}" class="page-btn">Next →</a>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIGMA Violations - caseScope 7.1</title>
        {get_theme_css()}    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            {render_sidebar_menu('violations')}
        </div>
        <div class="main-content">
            <div class="header">
                <div class="case-title">🚨 SIGMA Violations - Case: {case.name}</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                <h1>🚨 SIGMA Rule Violations</h1>
                
                <div class="stats-bar">
                    <div class="stat-item">
                        <div class="stat-value">{total_count}</div>
                        <div class="stat-label">Total</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value critical">{critical_count}</div>
                        <div class="stat-label">Critical</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value high">{high_count}</div>
                        <div class="stat-label">High</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value medium">{medium_count}</div>
                        <div class="stat-label">Medium</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value low">{low_count}</div>
                        <div class="stat-label">Low</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{reviewed_count}</div>
                        <div class="stat-label">Reviewed</div>
                    </div>
                </div>
                
                <div class="filter-bar">
                    <strong>Filters:</strong>
                    <select onchange="window.location.href='?severity='+this.value+'&rule={rule_filter}&file={file_filter}&reviewed={reviewed_filter}'">
                        <option value="all" {"selected" if severity_filter == "all" else ""}>All Severities</option>
                        <option value="critical" {"selected" if severity_filter == "critical" else ""}>Critical</option>
                        <option value="high" {"selected" if severity_filter == "high" else ""}>High</option>
                        <option value="medium" {"selected" if severity_filter == "medium" else ""}>Medium</option>
                        <option value="low" {"selected" if severity_filter == "low" else ""}>Low</option>
                    </select>
                    <select onchange="window.location.href='?severity={severity_filter}&rule='+this.value+'&file={file_filter}&reviewed={reviewed_filter}'">
                        <option value="all" {"selected" if rule_filter == "all" else ""}>All Rules</option>
                        {rule_options}
                    </select>
                    <select onchange="window.location.href='?severity={severity_filter}&rule={rule_filter}&file='+this.value+'&reviewed={reviewed_filter}'">
                        <option value="all" {"selected" if file_filter == "all" else ""}>All Files</option>
                        {file_options}
                    </select>
                    <select onchange="window.location.href='?severity={severity_filter}&rule={rule_filter}&file={file_filter}&reviewed='+this.value">
                        <option value="all" {"selected" if reviewed_filter == "all" else ""}>All Status</option>
                        <option value="unreviewed" {"selected" if reviewed_filter == "unreviewed" else ""}>Unreviewed</option>
                        <option value="reviewed" {"selected" if reviewed_filter == "reviewed" else ""}>Reviewed</option>
                    </select>
                </div>
                
                <table class="violations-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Rule</th>
                            <th>File</th>
                            <th>Event ID</th>
                            <th>Computer</th>
                            <th>Timestamp</th>
                            <th>Status</th>
                            <th>Actions</th>
                            <th>Tag</th>
                        </tr>
                    </thead>
                    <tbody>
                        {violations_html if violations_html else '<tr><td colspan="9" style="text-align: center; padding: 40px; color: #aaa;">No violations found with current filters.</td></tr>'}
                    </tbody>
                </table>
                
                {f'<div class="pagination">{pagination_html}</div>' if total_pages > 1 else ''}
            </div>
        </div>
        
        <script>
            function viewViolation(violationId) {{
                const row = document.getElementById('violation-details-' + violationId);
                if (row.style.display === 'none') {{
                    row.style.display = 'table-row';
                }} else {{
                    row.style.display = 'none';
                }}
            }}
            
            function showReviewModal(violationId) {{
                const notes = prompt('Add review notes (optional):');
                if (notes !== null) {{
                    const form = document.createElement('form');
                    form.method = 'POST';
                    form.action = '/violation/' + violationId + '/review';
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = 'notes';
                    input.value = notes;
                    form.appendChild(input);
                    document.body.appendChild(form);
                    form.submit();
                }}
            }}
            
            // Timeline tagging
            function toggleTag(button) {{
                const eventId = button.getAttribute('data-event-id');
                const timestamp = button.getAttribute('data-timestamp');
                const icon = button.querySelector('.tag-icon');
                const isTagged = icon.textContent === '★';
                
                if (isTagged) {{
                    // Untag
                    fetch('/api/event/untag', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{event_id: eventId}})
                    }})
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) {{
                            icon.textContent = '☆';
                            button.style.color = '#94a3b8';
                        }} else {{
                            alert('Failed to untag event: ' + (data.error || 'Unknown error'));
                        }}
                    }})
                    .catch(error => {{
                        console.error('Error:', error);
                        alert('Failed to untag event');
                    }});
                }} else {{
                    // Tag
                    fetch('/api/event/tag', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{
                            event_id: eventId,
                            timestamp: timestamp,
                            tag_type: 'timeline',
                            color: 'blue',
                            notes: ''
                        }})
                    }})
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) {{
                            icon.textContent = '★';
                            button.style.color = '#fbbf24';
                        }} else {{
                            alert('Failed to tag event: ' + (data.error || 'Unknown error'));
                        }}
                    }})
                    .catch(error => {{
                        console.error('Error:', error);
                        alert('Failed to tag event');
                    }});
                }}
            }}
            
            // Load existing tags on page load
            document.addEventListener('DOMContentLoaded', function() {{
                fetch('/api/event/tags?tag_type=timeline')
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) {{
                            const taggedEventIds = new Set(data.tags.map(t => t.event_id));
                            document.querySelectorAll('.tag-btn').forEach(button => {{
                                const eventId = button.getAttribute('data-event-id');
                                if (taggedEventIds.has(eventId)) {{
                                    const icon = button.querySelector('.tag-icon');
                                    icon.textContent = '★';
                                    button.style.color = '#fbbf24';
                                }}
                            }});
                        }}
                    }})
                    .catch(error => console.error('Error loading tags:', error));
                
                // Make event JSON interactive with IOC quick-add buttons
                makeJsonInteractive();
            }});
            
            // IOC Quick-Add Functionality
            function makeJsonInteractive() {{
                document.querySelectorAll('.event-json-interactive').forEach(container => {{
                    const jsonData = JSON.parse(container.getAttribute('data-event-json'));
                    container.innerHTML = renderInteractiveJson(jsonData, '');
                }});
            }}
            
            function renderInteractiveJson(obj, path) {{
                if (obj === null) return '<span style="color: #6b7280;">null</span>';
                if (typeof obj === 'boolean') return '<span style="color: #3b82f6;">' + obj + '</span>';
                if (typeof obj === 'number') return '<span style="color: #10b981;">' + obj + '</span>';
                if (typeof obj === 'string') {{
                    const escaped = obj.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                    const fullPath = path;
                    return `<span style="color: #f59e0b;">"${{escaped}}"</span><button class="ioc-add-btn" onclick="showIocModal('${{escaped}}', '${{fullPath}}')" title="Add as IOC">+</button>`;
                }}
                
                if (Array.isArray(obj)) {{
                    if (obj.length === 0) return '<span style="color: #6b7280;">[]</span>';
                    let html = '<span style="color: #6b7280;">[</span><div style="margin-left: 20px;">';
                    obj.forEach((item, i) => {{
                        html += renderInteractiveJson(item, path + '[' + i + ']');
                        if (i < obj.length - 1) html += '<span style="color: #6b7280;">,</span>';
                        html += '<br>';
                    }});
                    html += '</div><span style="color: #6b7280;">]</span>';
                    return html;
                }}
                
                if (typeof obj === 'object') {{
                    const keys = Object.keys(obj);
                    if (keys.length === 0) return '<span style="color: #6b7280;">{{}}</span>';
                    let html = '<span style="color: #6b7280;">{{</span><div style="margin-left: 20px;">';
                    keys.forEach((key, i) => {{
                        const keyPath = path ? path + '.' + key : key;
                        html += '<span style="color: #c084fc;">"' + key + '"</span><span style="color: #6b7280;">: </span>';
                        html += renderInteractiveJson(obj[key], keyPath);
                        if (i < keys.length - 1) html += '<span style="color: #6b7280;">,</span>';
                        html += '<br>';
                    }});
                    html += '</div><span style="color: #6b7280;">}}</span>';
                    return html;
                }}
                
                return String(obj);
            }}
            
            function showIocModal(value, fieldPath) {{
                document.getElementById('iocValue').value = value;
                document.getElementById('iocFieldPath').textContent = fieldPath || 'Unknown field';
                
                // Try to auto-detect IOC type from field name
                const suggestedType = detectIocType(fieldPath, value);
                document.getElementById('iocType').value = suggestedType;
                
                document.getElementById('iocQuickAddModal').style.display = 'flex';
            }}
            
            function detectIocType(fieldPath, value) {{
                const path = fieldPath.toLowerCase();
                
                // Pattern-based detection
                if (/^[0-9a-f]{{32}}$/i.test(value)) return 'hash_md5';
                if (/^[0-9a-f]{{40}}$/i.test(value)) return 'hash_sha1';
                if (/^[0-9a-f]{{64}}$/i.test(value)) return 'hash_sha256';
                if (/^(\\d{{1,3}}\\.){{3}}\\d{{1,3}}$/.test(value)) return 'ip';
                if (/@/.test(value)) return 'email';
                
                // Field name-based detection
                if (path.includes('computer') || path.includes('hostname')) return 'hostname';
                if (path.includes('domain')) return 'domain';
                if (path.includes('ip') || path.includes('address')) return 'ip';
                if (path.includes('username') || path.includes('user') || path.includes('account')) return 'username';
                if (path.includes('commandline') || path.includes('command')) return 'command';
                if (path.includes('process') || path.includes('image')) return 'process_name';
                if (path.includes('file') || path.includes('filename')) return 'filename';
                if (path.includes('hash') || path.includes('md5') || path.includes('sha')) {{
                    if (value.length === 32) return 'hash_md5';
                    if (value.length === 40) return 'hash_sha1';
                    if (value.length === 64) return 'hash_sha256';
                }}
                
                return 'command'; // Default fallback
            }}
            
            function closeIocModal() {{
                document.getElementById('iocQuickAddModal').style.display = 'none';
            }}
            
            function submitQuickIoc() {{
                const iocType = document.getElementById('iocType').value;
                const iocValue = document.getElementById('iocValue').value;
                const iocDescription = document.getElementById('iocDescription').value;
                const iocSeverity = document.getElementById('iocSeverity').value;
                
                if (!iocType || !iocValue) {{
                    alert('IOC type and value are required');
                    return;
                }}
                
                // Create form data
                const formData = new FormData();
                formData.append('action', 'add');
                formData.append('ioc_type', iocType);
                formData.append('ioc_value', iocValue);
                formData.append('description', iocDescription);
                formData.append('source', 'Quick Add from Event');
                formData.append('severity', iocSeverity);
                
                // Submit to existing IOC endpoint
                fetch('/ioc/list', {{
                    method: 'POST',
                    body: formData
                }})
                .then(response => {{
                    if (response.ok) {{
                        closeIocModal();
                        alert('✓ IOC added successfully!');
                        // Clear description field for next use
                        document.getElementById('iocDescription').value = '';
                    }} else {{
                        alert('Failed to add IOC. Please try again.');
                    }}
                }})
                .catch(error => {{
                    console.error('Error:', error);
                    alert('Failed to add IOC: ' + error);
                }});
            }}
        </script>
        
        <!-- IOC Quick Add Modal -->
        <div id="iocQuickAddModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 10000; align-items: center; justify-content: center;">
            <div style="background: #1e293b; border-radius: 8px; padding: 30px; max-width: 500px; width: 90%; box-shadow: 0 20px 60px rgba(0,0,0,0.5);">
                <h3 style="margin: 0 0 20px 0; color: #f1f5f9;">🎯 Quick Add IOC</h3>
                
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; color: #cbd5e1; font-weight: 600;">Field Path:</label>
                    <div id="iocFieldPath" style="padding: 8px 12px; background: #0f172a; border-radius: 4px; color: #94a3b8; font-family: monospace; font-size: 0.9em;"></div>
                </div>
                
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; color: #cbd5e1; font-weight: 600;">IOC Type:</label>
                    <select id="iocType" style="width: 100%; padding: 10px; background: #0f172a; color: #f1f5f9; border: 1px solid #334155; border-radius: 4px;">
                        <option value="ip">IP Address</option>
                        <option value="domain">Domain</option>
                        <option value="hostname">Hostname</option>
                        <option value="username">Username</option>
                        <option value="hash_md5">Hash (MD5)</option>
                        <option value="hash_sha1">Hash (SHA1)</option>
                        <option value="hash_sha256">Hash (SHA256)</option>
                        <option value="command">Command/Command Line</option>
                        <option value="filename">Filename</option>
                        <option value="process_name">Process Name</option>
                        <option value="malware_name">Malware Name</option>
                        <option value="registry_key">Registry Key</option>
                        <option value="email">Email Address</option>
                        <option value="url">URL</option>
                    </select>
                </div>
                
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; color: #cbd5e1; font-weight: 600;">IOC Value:</label>
                    <input type="text" id="iocValue" readonly style="width: 100%; padding: 10px; background: #0f172a; color: #f1f5f9; border: 1px solid #334155; border-radius: 4px; font-family: monospace;">
                </div>
                
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; color: #cbd5e1; font-weight: 600;">Description (Optional):</label>
                    <input type="text" id="iocDescription" placeholder="Why is this an IOC?" style="width: 100%; padding: 10px; background: #0f172a; color: #f1f5f9; border: 1px solid #334155; border-radius: 4px;">
                </div>
                
                <div style="margin-bottom: 20px;">
                    <label style="display: block; margin-bottom: 5px; color: #cbd5e1; font-weight: 600;">Severity:</label>
                    <select id="iocSeverity" style="width: 100%; padding: 10px; background: #0f172a; color: #f1f5f9; border: 1px solid #334155; border-radius: 4px;">
                        <option value="low">Low</option>
                        <option value="medium" selected>Medium</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                    </select>
                </div>
                
                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button onclick="closeIocModal()" style="padding: 10px 20px; background: #475569; color: #f1f5f9; border: none; border-radius: 4px; cursor: pointer; font-weight: 600;">Cancel</button>
                    <button onclick="submitQuickIoc()" style="padding: 10px 20px; background: linear-gradient(145deg, #22c55e, #16a34a); color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; box-shadow: 0 4px 12px rgba(34,197,94,0.3);">Add IOC</button>
                </div>
            </div>
        </div>
        
        <style>
            .ioc-add-btn {{
                display: inline-block;
                margin-left: 6px;
                padding: 2px 6px;
                background: linear-gradient(145deg, #22c55e, #16a34a);
                color: white;
                border: none;
                border-radius: 3px;
                cursor: pointer;
                font-weight: bold;
                font-size: 0.9em;
                box-shadow: 0 2px 4px rgba(34,197,94,0.2);
                transition: all 0.2s;
            }}
            .ioc-add-btn:hover {{
                background: linear-gradient(145deg, #16a34a, #15803d);
                box-shadow: 0 3px 8px rgba(34,197,94,0.4);
                transform: scale(1.05);
            }}
            .event-json-interactive {{
                background: #0f172a;
                padding: 15px;
                border-radius: 6px;
                font-family: 'Courier New', monospace;
                font-size: 0.9em;
                line-height: 1.6;
                overflow-x: auto;
                white-space: pre-wrap;
                word-break: break-all;
            }}
        </style>
    </body>
    </html>
    '''

def render_ioc_management_page(case, iocs, total_iocs, active_iocs, total_matches, iocs_with_matches,
                                type_filter, severity_filter, status_filter, ioc_types):
    """Render IOC Management Page"""
    from flask import get_flashed_messages
    
    # Flash messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    # Build IOCs table
    iocs_html = ""
    for ioc in iocs:
        # Severity color
        severity_colors = {
            'critical': '#d32f2f',
            'high': '#f44336',
            'medium': '#ff9800',
            'low': '#2196f3'
        }
        severity_color = severity_colors.get(ioc.severity, '#757575')
        
        # Status badge
        status_badge = '<span style="color: #4caf50;">✓ Active</span>' if ioc.is_active else '<span style="color: #757575;">✗ Inactive</span>'
        
        # Escape values for HTML (must be done before using in match_badge)
        import html
        ioc_value_safe = html.escape(ioc.ioc_value, quote=True)
        description_safe = html.escape(ioc.description or 'No description', quote=True)
        
        # Match count badge (clickable if there are matches)
        if ioc.match_count > 0:
            match_badge = f'<a href="/search?ioc={ioc_value_safe}" style="color: #fbbf24; font-weight: bold; text-decoration: none; cursor: pointer;" title="View {ioc.match_count} matching events">🎯 {ioc.match_count}</a>'
        else:
            match_badge = '<span style="color: #94a3b8;">0</span>'
        
        # Last hunted info
        last_hunted = ioc.last_hunted.strftime('%Y-%m-%d %H:%M') if ioc.last_hunted else 'Never'
        
        iocs_html += f'''
        <tr>
            <td><span style="background: #1e293b; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 0.85rem;">{ioc.ioc_type}</span></td>
            <td style="font-family: monospace; color: #60a5fa;">{ioc_value_safe[:50]}{('...' if len(ioc_value_safe) > 50 else '')}</td>
            <td>{description_safe[:60]}{('...' if len(description_safe) > 60 else '')}</td>
            <td><span style="color: {severity_color}; font-weight: bold;">{ioc.severity.upper()}</span></td>
            <td>{status_badge}</td>
            <td style="text-align: center;">{match_badge}</td>
            <td style="font-size: 0.85rem; color: #94a3b8;">{last_hunted}</td>
            <td>
                <button class="btn-action" onclick="editIOC({ioc.id}, '{ioc_value_safe}', '{description_safe}', '{ioc.source or ''}', '{ioc.severity}', '{ioc.notes or ''}', {('true' if ioc.is_active else 'false')})" title="Edit">✏️</button>
                <form method="POST" action="/ioc/delete/{ioc.id}" style="display: inline;" onsubmit="return confirm('Delete this IOC and all its matches?');">
                    <button type="submit" class="btn-action" style="color: #f44336;" title="Delete">🗑️</button>
                </form>
            </td>
        </tr>
        '''
    
    if not iocs_html:
        iocs_html = '<tr><td colspan="8" style="text-align: center; padding: 40px; color: #aaa;">No IOCs found. Add your first IOC to start threat hunting.</td></tr>'
    
    # IOC type options for filter and add form
    all_ioc_types = ['ip', 'domain', 'fqdn', 'hostname', 'username', 'hash_md5', 'hash_sha1', 'hash_sha256', 'command', 'filename', 'process_name', 'malware_name', 'registry_key', 'email', 'url']
    type_options = ''.join([f'<option value="{t}" {"selected" if type_filter == t else ""}>{t.replace("_", " ").title()}</option>' for t in all_ioc_types])
    type_add_options = ''.join([f'<option value="{t}">{t.replace("_", " ").title()}</option>' for t in all_ioc_types])
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>IOC Management - {case.name} - caseScope 7.14</title>
        {get_theme_css()}
    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            {render_sidebar_menu('ioc_management')}
        </div>
        
        <div class="main-content">
            <div class="header">
                <div class="case-title">🎯 IOC Management - {case.name}</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                {flash_messages_html}
            
            <div class="stats-bar">
                <div class="stat-card">
                    <div class="stat-value">{total_iocs}</div>
                    <div class="stat-label">Total IOCs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #4caf50;">{active_iocs}</div>
                    <div class="stat-label">Active</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #fbbf24;">{total_matches}</div>
                    <div class="stat-label">Total Matches</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #60a5fa;">{iocs_with_matches}</div>
                    <div class="stat-label">IOCs with Matches</div>
                </div>
            </div>
            
            <div class="search-box" style="display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; align-items: center;">
                <button onclick="showAddIOCModal()" class="btn-primary">+ Add IOC</button>
                <button onclick="window.location.href='/ioc/hunt'" class="btn-primary" style="background: #fbbf24;">🔍 Hunt Now</button>
                <button onclick="window.location.href='/ioc/matches'" class="btn-primary" style="background: #60a5fa;">📋 View Matches</button>
                
                <div style="flex: 1; display: flex; gap: 10px; justify-content: flex-end;">
                    <select onchange="filterIOCs()" id="typeFilter" style="padding: 8px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;">
                        <option value="all">All Types</option>
                        {type_options}
                    </select>
                    <select onchange="filterIOCs()" id="severityFilter" style="padding: 8px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;">
                        <option value="all" {"selected" if severity_filter == "all" else ""}>All Severities</option>
                        <option value="critical" {"selected" if severity_filter == "critical" else ""}>Critical</option>
                        <option value="high" {"selected" if severity_filter == "high" else ""}>High</option>
                        <option value="medium" {"selected" if severity_filter == "medium" else ""}>Medium</option>
                        <option value="low" {"selected" if severity_filter == "low" else ""}>Low</option>
                    </select>
                    <select onchange="filterIOCs()" id="statusFilter" style="padding: 8px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;">
                        <option value="all" {"selected" if status_filter == "all" else ""}>All Status</option>
                        <option value="active" {"selected" if status_filter == "active" else ""}>Active</option>
                        <option value="inactive" {"selected" if status_filter == "inactive" else ""}>Inactive</option>
                    </select>
                </div>
            </div>
            
            <table class="results-table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Value</th>
                        <th>Description</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Matches</th>
                        <th>Last Hunted</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {iocs_html}
                </tbody>
            </table>
            </div>
        </div>
        
        <!-- Add IOC Modal -->
        <div id="addIOCModal" class="modal" style="display: none;">
            <div class="modal-content" style="max-width: 600px;">
                <span class="close" onclick="closeAddIOCModal()">&times;</span>
                <h2>➕ Add IOC</h2>
                <form method="POST" action="/ioc/list">
                    <input type="hidden" name="action" value="add">
                    
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: bold;">IOC Type *</label>
                        <select name="ioc_type" required style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;">
                            {type_add_options}
                        </select>
                    </div>
                    
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: bold;">IOC Value *</label>
                        <input type="text" name="ioc_value" required placeholder="e.g., 192.168.1.100, malware.exe, abc123..." style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;">
                    </div>
                    
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: bold;">Description</label>
                        <textarea name="description" rows="2" placeholder="What this IOC represents..." style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;"></textarea>
                    </div>
                    
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: bold;">Source</label>
                        <input type="text" name="source" placeholder="e.g., Threat Intel, VirusTotal, Manual Analysis" style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;">
                    </div>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: bold;">Severity</label>
                            <select name="severity" style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;">
                                <option value="low">Low</option>
                                <option value="medium" selected>Medium</option>
                                <option value="high">High</option>
                                <option value="critical">Critical</option>
                            </select>
                        </div>
                    </div>
                    
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: bold;">Notes</label>
                        <textarea name="notes" rows="2" placeholder="Additional analyst notes..." style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;"></textarea>
                    </div>
                    
                    <div style="display: flex; gap: 10px; justify-content: flex-end;">
                        <button type="button" onclick="closeAddIOCModal()" style="padding: 10px 20px; background: #475569; border: none; border-radius: 6px; color: white; cursor: pointer;">Cancel</button>
                        <button type="submit" style="padding: 10px 20px; background: #3b82f6; border: none; border-radius: 6px; color: white; cursor: pointer; font-weight: bold;">Add IOC</button>
                    </div>
                </form>
            </div>
        </div>
        
        <!-- Edit IOC Modal -->
        <div id="editIOCModal" class="modal" style="display: none;">
            <div class="modal-content" style="max-width: 600px;">
                <span class="close" onclick="closeEditIOCModal()">&times;</span>
                <h2>✏️ Edit IOC</h2>
                <form method="POST" id="editIOCForm">
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: bold;">IOC Value</label>
                        <input type="text" id="editValue" readonly style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #94a3b8;">
                    </div>
                    
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: bold;">Description</label>
                        <textarea name="description" id="editDescription" rows="2" style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;"></textarea>
                    </div>
                    
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: bold;">Source</label>
                        <input type="text" name="source" id="editSource" style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;">
                    </div>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: bold;">Severity</label>
                            <select name="severity" id="editSeverity" style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;">
                                <option value="low">Low</option>
                                <option value="medium">Medium</option>
                                <option value="high">High</option>
                                <option value="critical">Critical</option>
                            </select>
                        </div>
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: bold;">Status</label>
                            <select name="is_active" id="editStatus" style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;">
                                <option value="true">Active</option>
                                <option value="false">Inactive</option>
                            </select>
                        </div>
                    </div>
                    
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: bold;">Notes</label>
                        <textarea name="notes" id="editNotes" rows="2" style="width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;"></textarea>
                    </div>
                    
                    <div style="display: flex; gap: 10px; justify-content: flex-end;">
                        <button type="button" onclick="closeEditIOCModal()" style="padding: 10px 20px; background: #475569; border: none; border-radius: 6px; color: white; cursor: pointer;">Cancel</button>
                        <button type="submit" style="padding: 10px 20px; background: #3b82f6; border: none; border-radius: 6px; color: white; cursor: pointer; font-weight: bold;">Update IOC</button>
                    </div>
                </form>
            </div>
        </div>
        
        <script>
            function showAddIOCModal() {{
                document.getElementById('addIOCModal').style.display = 'flex';
            }}
            
            function closeAddIOCModal() {{
                document.getElementById('addIOCModal').style.display = 'none';
            }}
            
            function editIOC(id, value, description, source, severity, notes, isActive) {{
                document.getElementById('editValue').value = value;
                document.getElementById('editDescription').value = description;
                document.getElementById('editSource').value = source;
                document.getElementById('editSeverity').value = severity;
                document.getElementById('editStatus').value = isActive.toString();
                document.getElementById('editNotes').value = notes;
                document.getElementById('editIOCForm').action = '/ioc/edit/' + id;
                document.getElementById('editIOCModal').style.display = 'flex';
            }}
            
            function closeEditIOCModal() {{
                document.getElementById('editIOCModal').style.display = 'none';
            }}
            
            function filterIOCs() {{
                const type = document.getElementById('typeFilter').value;
                const severity = document.getElementById('severityFilter').value;
                const status = document.getElementById('statusFilter').value;
                window.location.href = '/ioc/list?type=' + type + '&severity=' + severity + '&status=' + status;
            }}
            
            // Close modals when clicking outside
            window.onclick = function(event) {{
                if (event.target.className === 'modal') {{
                    event.target.style.display = 'none';
                }}
            }}
        </script>
    </body>
    </html>
    '''

def render_ioc_matches_page(case, matches, total_matches, page, per_page, ioc_filter, type_filter, 
                            hunt_type_filter, all_iocs, total_count, manual_count, automatic_count,
                            unique_iocs, unique_events):
    """Render IOC Matches Page"""
    from flask import get_flashed_messages
    import html
    
    # Flash messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    # Build matches table
    matches_html = ""
    for match in matches:
        # Get IOC details
        ioc = match.ioc
        
        # IOC type color
        type_colors = {
            'ip': '#60a5fa',
            'domain': '#34d399',
            'hostname': '#a78bfa',
            'username': '#f472b6',
            'hash_md5': '#fbbf24',
            'hash_sha1': '#fb923c',
            'hash_sha256': '#f87171',
            'command': '#38bdf8',
            'filename': '#4ade80'
        }
        type_color = type_colors.get(ioc.ioc_type, '#64748b')
        
        # Hunt type badge
        hunt_badge = '🤖 Auto' if match.hunt_type == 'automatic' else '👤 Manual'
        hunt_color = '#3b82f6' if match.hunt_type == 'automatic' else '#10b981'
        
        # Escape values
        ioc_value_safe = html.escape(ioc.ioc_value[:50], quote=True)
        matched_field_safe = html.escape(match.matched_field or 'unknown', quote=True)
        matched_value_safe = html.escape(match.matched_value[:60] if match.matched_value else 'N/A', quote=True)
        filename_safe = html.escape(match.source_filename or 'Unknown', quote=True)
        
        matches_html += f'''
        <tr class="match-row">
            <td><span style="background: {type_color}; padding: 4px 8px; border-radius: 4px; font-size: 0.85rem; font-weight: bold;">{ioc.ioc_type.upper()}</span></td>
            <td style="font-family: monospace; color: #60a5fa;">{ioc_value_safe}</td>
            <td style="font-family: monospace; font-size: 0.85rem; color: #34d399;">{matched_field_safe}</td>
            <td style="font-family: monospace; font-size: 0.9rem;">{matched_value_safe}</td>
            <td>{match.event_timestamp[:19] if match.event_timestamp and len(match.event_timestamp) > 19 else match.event_timestamp or 'N/A'}</td>
            <td style="color: #60a5fa; font-size: 0.9rem;">{filename_safe}</td>
            <td><span style="color: {hunt_color}; font-weight: bold;">{hunt_badge}</span></td>
            <td>{match.event_timestamp[:19] if match.event_timestamp and len(match.event_timestamp) > 19 else match.event_timestamp or 'N/A'}</td>
            <td class="actions-cell">
                <a href="/search?event_id={match.event_id}" class="btn-action btn-view" title="View Event">👁️</a>
            </td>
        </tr>
        '''
    
    # Build filter dropdowns
    ioc_options = ''.join([f'<option value="{ioc.id}" {"selected" if str(ioc.id) == ioc_filter else ""}>{ioc.ioc_type}:{ioc.ioc_value[:30]}</option>' for ioc in all_iocs])
    
    # Get unique IOC types for type filter
    ioc_types = ['ip', 'domain', 'fqdn', 'hostname', 'username', 'hash_md5', 'hash_sha1', 'hash_sha256', 'command', 'filename', 'process_name', 'malware_name', 'registry_key', 'email', 'url']
    type_options = ''.join([f'<option value="{t}" {"selected" if t == type_filter else ""}>{t.replace("_", " ").title()}</option>' for t in ioc_types])
    
    # Pagination
    total_pages = (total_matches + per_page - 1) // per_page
    pagination_html = ""
    if total_pages > 1:
        if page > 1:
            pagination_html += f'<a href="?page={page-1}&ioc={ioc_filter}&type={type_filter}&hunt_type={hunt_type_filter}" class="page-btn">← Previous</a>'
        pagination_html += f'<span class="page-info">Page {page} of {total_pages}</span>'
        if page < total_pages:
            pagination_html += f'<a href="?page={page+1}&ioc={ioc_filter}&type={type_filter}&hunt_type={hunt_type_filter}" class="page-btn">Next →</a>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>IOC Matches - caseScope 7.14</title>
        {get_theme_css()}
        <style>
            .match-row {{
                transition: background 0.2s ease;
            }}
            .match-row:hover {{
                background: #1e293b;
            }}
            .stats-container {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1rem;
                margin-bottom: 2rem;
            }}
            .stat-box {{
                background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
                padding: 1.5rem;
                border-radius: 12px;
                border: 1px solid #334155;
                text-align: center;
            }}
            .stat-box .value {{
                font-size: 2.5rem;
                font-weight: bold;
                margin-bottom: 0.5rem;
            }}
            .stat-box .label {{
                color: #94a3b8;
                font-size: 0.9rem;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            {render_sidebar_menu('ioc_matches')}
        </div>
        <div class="main-content">
            <div class="header">
                <div class="case-title">🎯 IOC Matches - Case: {case.name}</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                {flash_messages_html}
                
                <h1>🎯 IOC Matches Found</h1>
                
                <div class="stats-container">
                    <div class="stat-box">
                        <div class="value" style="color: #3b82f6;">{total_count}</div>
                        <div class="label">Total Matches</div>
                    </div>
                    <div class="stat-box">
                        <div class="value" style="color: #10b981;">{unique_iocs}</div>
                        <div class="label">Unique IOCs</div>
                    </div>
                    <div class="stat-box">
                        <div class="value" style="color: #fbbf24;">{unique_events}</div>
                        <div class="label">Affected Events</div>
                    </div>
                    <div class="stat-box">
                        <div class="value" style="color: #3b82f6;">{automatic_count}</div>
                        <div class="label">Automatic</div>
                    </div>
                    <div class="stat-box">
                        <div class="value" style="color: #10b981;">{manual_count}</div>
                        <div class="label">Manual</div>
                    </div>
                </div>
                
                <div class="filter-bar" style="display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap;">
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <strong>Filters:</strong>
                        <select onchange="window.location.href='?ioc='+this.value+'&type={type_filter}&hunt_type={hunt_type_filter}'" style="padding: 8px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;">
                            <option value="all" {"selected" if ioc_filter == "all" else ""}>All IOCs</option>
                            {ioc_options}
                        </select>
                        <select onchange="window.location.href='?ioc={ioc_filter}&type='+this.value+'&hunt_type={hunt_type_filter}'" style="padding: 8px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;">
                            <option value="all" {"selected" if type_filter == "all" else ""}>All Types</option>
                            {type_options}
                        </select>
                        <select onchange="window.location.href='?ioc={ioc_filter}&type={type_filter}&hunt_type='+this.value" style="padding: 8px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: white;">
                            <option value="all" {"selected" if hunt_type_filter == "all" else ""}>All Hunt Types</option>
                            <option value="automatic" {"selected" if hunt_type_filter == "automatic" else ""}>Automatic</option>
                            <option value="manual" {"selected" if hunt_type_filter == "manual" else ""}>Manual</option>
                        </select>
                    </div>
                    <div style="margin-left: auto;">
                        <button onclick="window.location.href='/ioc/list'" class="btn-primary">← Back to IOCs</button>
                    </div>
                </div>
                
                {f'<div class="pagination-container">{pagination_html}</div>' if pagination_html else ''}
                
                <table class="results-table">
                    <thead>
                        <tr>
                            <th>IOC Type</th>
                            <th>IOC Value</th>
                            <th>Matched Field</th>
                            <th>Matched Value</th>
                            <th>Event Time</th>
                            <th>Source File</th>
                            <th>Hunt Type</th>
                            <th>Event Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {matches_html if matches_html else '<tr><td colspan="9" style="text-align: center; padding: 2rem; color: #64748b;">No IOC matches found. Try adjusting your filters or running a hunt.</td></tr>'}
                    </tbody>
                </table>
                
                {f'<div class="pagination-container">{pagination_html}</div>' if pagination_html else ''}
            </div>
        </div>
    </body>
    </html>
    '''

def render_case_form(users=None):
    """Render case creation form with sidebar layout"""
    if users is None:
        users = []
    
    sidebar_menu = render_sidebar_menu('case_select')
    
    # Build assignee options
    assignee_options = '<option value="">-- Unassigned --</option>'
    for user in users:
        assignee_options += f'<option value="{user.id}">{user.username}</option>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Create New Case - caseScope 7.1</title>
        {get_theme_css()}    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                📁 caseScope
                <div class="version-badge">v{APP_VERSION}</div>
            </div>
            {sidebar_menu}
        </div>
        <div class="main-content">
            <div class="form-container">
                <h2>Create New Case</h2>
                <form method="POST">
                <div class="form-group">
                    <label for="name">Case Name *</label>
                    <input type="text" id="name" name="name" required placeholder="Enter case name">
                </div>
                <div class="form-group">
                    <label for="description">Description</label>
                    <textarea id="description" name="description" placeholder="Enter case description (optional)"></textarea>
                </div>
                <div class="form-group">
                    <label for="company">Company/Customer Name</label>
                    <input type="text" id="company" name="company" placeholder="e.g., Acme Corporation, City Police Department">
                    <small style="color: #94a3b8; display: block; margin-top: 0.3rem;">Used for DFIR-IRIS integration (optional)</small>
                </div>
                <div class="form-group">
                    <label for="priority">Priority</label>
                    <select id="priority" name="priority">
                        <option value="Low">Low</option>
                        <option value="Medium" selected>Medium</option>
                        <option value="High">High</option>
                        <option value="Critical">Critical</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="assignee_id">Assign To (optional)</label>
                    <select id="assignee_id" name="assignee_id">
                        {assignee_options}
                    </select>
                </div>
                <div class="form-group">
                    <label for="tags">Tags (comma-separated)</label>
                    <input type="text" id="tags" name="tags" placeholder="e.g., malware, ransomware, data-breach">
                </div>
                <div style="text-align: center; margin-top: 25px;">
                    <button type="submit">Create Case</button>
                    <button type="button" class="cancel-btn" onclick="window.location.href='/dashboard'">Cancel</button>
                </div>
            </form>
            </div>
        </div>
    </body>
    </html>
    '''

def render_case_selection(cases, active_case_id):
    """Render case selection page with integrated layout"""
    # Get flash messages
    from flask import get_flashed_messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    case_rows = ""
    for case in cases:
        active_class = "active-case" if case.id == active_case_id else ""
        sync_badge = '<span class="sync-badge-small sync-synced">✓ Synced</span>' if case.iris_synced_at else '<span class="sync-badge-small sync-not-synced">⚠</span>'
        case_rows += f'''
        <tr class="case-row {active_class}" onclick="selectCase({case.id})">
            <td>{case.case_number}</td>
            <td>{case.name}</td>
            <td><span class="priority-{case.priority.lower()}">{case.priority}</span></td>
            <td><span class="status-{case.status.lower().replace(' ', '-')}">{case.status}</span></td>
            <td>{case.file_count}</td>
            <td>{case.created_at.strftime('%Y-%m-%d')}</td>
            <td>{case.creator.username}</td>
            <td>{sync_badge}</td>
            <td>{'✓ Active' if case.id == active_case_id else ''}</td>
        </tr>
        '''
    
    # Use the main dashboard layout but with case selection content
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Case Selection - caseScope 7.1</title>
        {get_theme_css()}
        <style>
            /* Page-specific overrides for Case Selection */
            .case-row.active-case {{
                background: rgba(76,175,80,0.15);
                border-left: 4px solid var(--accent-green);
            }}
            
            /* Small sync badges for table */
            .sync-badge-small {{
                display: inline-block;
                padding: 4px 10px;
                border-radius: 12px;
                font-size: 11px;
                font-weight: 600;
                box-shadow: 0 1px 3px rgba(0,0,0,0.2);
            }}
            .sync-synced {{
                background: linear-gradient(135deg, #4caf50, #388e3c);
                color: white;
            }}
            .sync-not-synced {{
                background: linear-gradient(135deg, #ff9800, #f57c00);
                color: white;
            }}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            {render_sidebar_menu('case_select')}
        </div>
        <div class="main-content">
            <div class="header">
                <div class="case-title">📁 Case Selection</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                {flash_messages_html}
                <p>Select a case to work with or create a new one</p>
                
                <div class="search-container">
                    <input type="text" class="search-input" placeholder="Search cases by name..." id="caseSearch" onkeyup="filterCases()">
                    <a href="/case/create" class="create-btn">➕ Create New Case</a>
                </div>
                
                <table class="case-table">
                    <thead>
                        <tr>
                            <th>Case Number</th>
                            <th>Name</th>
                            <th>Priority</th>
                            <th>Status</th>
                            <th>Files</th>
                            <th>Created</th>
                            <th>Created By</th>
                            <th>IRIS Sync</th>
                            <th>Active</th>
                        </tr>
                    </thead>
                    <tbody id="caseTableBody">
                        {case_rows}
                    </tbody>
                </table>
            </div>
        </div>
        
        <script>
            function selectCase(caseId) {{
                window.location.href = '/case/set/' + caseId;
            }}
            
            function filterCases() {{
                const searchTerm = document.getElementById('caseSearch').value.toLowerCase();
                const rows = document.querySelectorAll('.case-row');
                
                rows.forEach(row => {{
                    const caseName = row.cells[1].textContent.toLowerCase();
                    const caseNumber = row.cells[0].textContent.toLowerCase();
                    
                    if (caseName.includes(searchTerm) || caseNumber.includes(searchTerm)) {{
                        row.style.display = '';
                    }} else {{
                        row.style.display = 'none';
                    }}
                }});
            }}
        </script>
    </body>
    </html>
    '''

def render_case_dashboard(case, total_files, indexed_files, processing_files, total_events, total_violations, total_storage,
                          total_sigma_rules, enabled_sigma_rules, total_iocs, total_ioc_matches):
    """Render case-specific dashboard with integrated layout"""
    # Get flash messages
    from flask import get_flashed_messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Case Dashboard - {case.name} - caseScope 7.1</title>
        {get_theme_css()}
        <style>
            /* Page-specific styles for Case Dashboard */
            .case-title {{
                font-size: 1.3em;
                font-weight: 600;
                color: var(--text-primary);
            }}
            .header {{
                display: flex;
                justify-content: space-between;
            }}
            .case-info {{
                background: var(--bg-card);
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 25px;
                box-shadow: var(--shadow-sm);
                border: 1px solid var(--border-default);
            }}
            .tiles {{ 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
                gap: 25px; 
            }}
            .tile {{
                cursor: pointer;
                transition: transform 0.2s ease, box-shadow 0.2s ease;
            }}
            .tile:hover {{
                transform: translateY(-3px);
                box-shadow: 0 8px 16px rgba(0,0,0,0.3);
            }}
            .actions {{ 
                margin-top: 25px; 
                text-align: center; 
            }}
            .btn {{ 
                background: var(--accent-green);
                color: white; 
                padding: 12px 24px; 
                text-decoration: none; 
                border-radius: 6px; 
                margin: 0 10px 10px 10px;
                display: inline-block;
                transition: all 0.2s ease;
                font-weight: 500;
                border: none;
            }}
            .btn:hover {{ 
                background: #43a047;
            }}
            .btn-secondary {{ 
                background: var(--accent-blue);
            }}
            .btn-secondary:hover {{ 
                background: #1976d2;
            }}
            
            /* Sync Status Badges */
            .sync-badge {{
                display: inline-block;
                padding: 6px 14px;
                border-radius: 20px;
                font-size: 13px;
                font-weight: 600;
                letter-spacing: 0.3px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            }}
            .sync-badge-synced {{
                background: linear-gradient(135deg, #4caf50, #388e3c);
                color: white;
            }}
            .sync-badge-not-synced {{
                background: linear-gradient(135deg, #ff9800, #f57c00);
                color: white;
            }}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            {render_sidebar_menu('case_dashboard')}
        </div>
        <div class="main-content">
            <div class="header">
                <div class="case-title">📁 {case.name}</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                {flash_messages_html}
                <div class="case-info">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h2>Case Details</h2>
                        {'<span class="sync-badge sync-badge-synced">✓ Synced to IRIS</span>' if case.iris_synced_at else '<span class="sync-badge sync-badge-not-synced">⚠ Not Synced</span>'}
                    </div>
                    <p><strong>Case Number:</strong> {case.case_number}</p>
                    <p><strong>Description:</strong> {case.description or 'No description provided'}</p>
                    <p><strong>Priority:</strong> {case.priority} | <strong>Status:</strong> {case.status}</p>
                    <p><strong>Created:</strong> {case.created_at.strftime('%Y-%m-%d %H:%M')} by {case.creator.username}</p>
                    {f'<p><strong>DFIR-IRIS Sync:</strong> Last synced {case.iris_synced_at.strftime("%Y-%m-%d %H:%M")} (Case ID: {case.iris_case_id})</p>' if case.iris_synced_at else ''}
                </div>
                
                <div class="tiles">
                    <div class="tile" onclick="window.location.href='/files';" title="Click to view files">
                        <h3>📄 Files</h3>
                        <p><strong>Total Files:</strong> {total_files:,}</p>
                        <p><strong>Indexed:</strong> {indexed_files:,} / {total_files:,}</p>
                        <p><strong>Processing:</strong> {processing_files:,}</p>
                        <p><strong>Storage:</strong> {total_storage / (1024*1024*1024):.2f} GB</p>
                        <button onclick="event.stopPropagation(); window.location.href='/files';" class="btn" style="background: linear-gradient(145deg, #607d8b, #455a64); box-shadow: 0 4px 8px rgba(96,125,139,0.3); border: none; cursor: pointer; font-weight: 600;">📁 Manage Files</button>
                    </div>
                    <div class="tile" onclick="window.location.href='/search';" title="Click to search events">
                        <h3>📊 Events</h3>
                        <p><strong>Total Events:</strong> {total_events:,}</p>
                        <p><strong>Indexed Files:</strong> {indexed_files:,}</p>
                        <p><strong>Searchable:</strong> {'Yes' if indexed_files > 0 else 'No files indexed yet'}</p>
                        <p><strong>Event IDs:</strong> 100+ Mapped</p>
                        <div style="margin-top: 15px;">
                            <button onclick="event.stopPropagation(); window.location.href='/search';" class="btn" style="background: linear-gradient(145deg, #4caf50, #388e3c); box-shadow: 0 4px 8px rgba(76,175,80,0.3); margin: 5px; border: none; cursor: pointer; font-weight: 600;">🔍 Search Events</button>
                            <button onclick="event.stopPropagation(); reindexAllFiles();" class="btn" style="background: linear-gradient(145deg, #2196f3, #1976d2); box-shadow: 0 4px 8px rgba(33,150,243,0.3); margin: 5px; border: none; cursor: pointer; font-weight: 600;">🔄 Re-index All Files</button>
                        </div>
                    </div>
                    <div class="tile" onclick="window.location.href='/search?threat_filter=either';" title="Click to view SIGMA and IOC detections">
                        <h3>🛡️ SIGMA Rules & IOCs</h3>
                        <p><strong>Violations Found:</strong> {total_violations:,}</p>
                        <p><strong>Files Scanned:</strong> {indexed_files:,}</p>
                        <p><strong>SIGMA Rules:</strong> <span style="color: #4caf50; font-weight: 600;">{enabled_sigma_rules:,}</span> / {total_sigma_rules:,} enabled</p>
                        <p><strong>IOCs Tracked:</strong> {total_iocs:,} ({total_ioc_matches:,} matches)</p>
                        <p><strong>Auto-Processing:</strong> <span style="color: #4caf50; font-weight: 600;">✓ Active</span></p>
                        <div style="margin-top: 15px;">
                            <button onclick="event.stopPropagation(); rerunAllRules();" class="btn" style="background: linear-gradient(145deg, #ff9800, #f57c00); box-shadow: 0 4px 8px rgba(255,152,0,0.3); border: none; cursor: pointer; font-weight: 600;">⚡ Re-run All Rules</button>
                        </div>
                    </div>
                </div>
                
                <div class="actions">
                    <button onclick="window.location.href='/upload';" class="btn" style="background: linear-gradient(145deg, #00bcd4, #0097a7); box-shadow: 0 4px 8px rgba(0,188,212,0.3); border: none; cursor: pointer; font-weight: 600;">📤 Upload Files</button>
                    <button onclick="syncToIris()" class="btn" style="background: linear-gradient(145deg, #9c27b0, #7b1fa2); box-shadow: 0 4px 8px rgba(156,39,176,0.3); border: none; cursor: pointer; font-weight: 600;">🔗 Sync to DFIR-IRIS</button>
                    <button onclick="window.location.href='/case/select';" class="btn" style="background: linear-gradient(145deg, #607d8b, #455a64); box-shadow: 0 4px 8px rgba(96,125,139,0.3); border: none; cursor: pointer; font-weight: 600;">🔄 Switch Case</button>
                    <button onclick="window.location.href='/dashboard';" class="btn" style="background: linear-gradient(145deg, #607d8b, #455a64); box-shadow: 0 4px 8px rgba(96,125,139,0.3); border: none; cursor: pointer; font-weight: 600;">🏠 Main Dashboard</button>
                </div>
            </div>
        </div>
        
        <script>
            function reindexAllFiles() {{
                if (!confirm('This will re-index ALL files in this case. Existing events will be removed and re-created. This may take several minutes. Continue?')) {{
                    return;
                }}
                
                fetch('/api/reindex-all-files', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{ case_id: {case.id} }})
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        alert('Successfully queued ' + data.files_queued + ' file(s) for re-indexing.');
                        location.reload();
                    }} else {{
                        alert('Error: ' + (data.message || 'Failed to queue files for re-indexing'));
                    }}
                }})
                .catch(error => {{
                    alert('Error: ' + error.message);
                }});
            }}
            
            function rerunAllRules() {{
                if (!confirm('This will re-run SIGMA rules on ALL indexed files in this case. This may take several minutes. Continue?')) {{
                    return;
                }}
                
                fetch('/api/rerun-all-rules', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{ case_id: {case.id} }})
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        alert('Successfully queued ' + data.files_queued + ' file(s) for SIGMA rule processing.');
                        location.reload();
                    }} else {{
                        alert('Error: ' + (data.message || 'Failed to queue files for processing'));
                    }}
                }})
                .catch(error => {{
                    alert('Error: ' + error.message);
                }});
            }}
            
            function syncToIris() {{
                // Show confirmation
                const confirmMsg = 'This will sync this case to DFIR-IRIS:\\n\\n' +
                                  '1. Create/update company in IRIS\\n' +
                                  '2. Create/update case in IRIS\\n' +
                                  '3. Sync all IOCs\\n' +
                                  '4. Sync timeline events\\n\\n' +
                                  'This may take a minute. Continue?';
                
                if (!confirm(confirmMsg)) {{
                    return;
                }}
                
                // Disable button and show progress
                const btn = event.target;
                const originalText = btn.innerHTML;
                btn.disabled = true;
                btn.innerHTML = '⏳ Syncing...';
                btn.style.opacity = '0.6';
                
                fetch('/iris/sync', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }}
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) {{
                        // Build success message with stats
                        let msg = '✅ Sync completed successfully!\\n\\n';
                        if (data.iris_case_id) {{
                            msg += 'IRIS Case ID: ' + data.iris_case_id + '\\n';
                        }}
                        if (data.iocs_synced !== undefined) {{
                            msg += 'IOCs synced: ' + data.iocs_synced + ' new';
                            if (data.iocs_skipped) {{
                                msg += ', ' + data.iocs_skipped + ' already exist';
                            }}
                            msg += '\\n';
                        }}
                        if (data.timeline_synced !== undefined) {{
                            msg += 'Timeline events: ' + data.timeline_synced + ' new';
                            if (data.timeline_skipped) {{
                                msg += ', ' + data.timeline_skipped + ' already exist';
                            }}
                            msg += '\\n';
                        }}
                        alert(msg);
                        location.reload();
                    }} else {{
                        alert('❌ Sync failed:\\n\\n' + (data.message || 'Unknown error'));
                        btn.disabled = false;
                        btn.innerHTML = originalText;
                        btn.style.opacity = '1';
                    }}
                }})
                .catch(error => {{
                    alert('❌ Error: ' + error.message);
                    btn.disabled = false;
                    btn.innerHTML = originalText;
                    btn.style.opacity = '1';
                }});
            }}
        </script>
    </body>
    </html>
    '''

# SIGMA Rules Management
def load_default_sigma_rules():
    """Load built-in SIGMA rules on first run"""
    import hashlib
    
    # Check if we already have built-in rules
    existing_count = db.session.query(SigmaRule).filter_by(is_builtin=True).count()
    if existing_count > 0:
        print(f"Built-in SIGMA rules already loaded ({existing_count} rules)")
        return
    
    print("Loading default SIGMA rules...")
    
    # Common Windows Security SIGMA rules
    default_rules = [
        {
            'name': 'suspicious_powershell_execution',
            'title': 'Suspicious PowerShell Execution',
            'description': 'Detects suspicious PowerShell command execution patterns',
            'author': 'caseScope Team',
            'level': 'medium',
            'status': 'stable',
            'category': 'process_creation',
            'tags': json.dumps(['powershell', 'execution', 'suspicious']),
            'rule_yaml': '''
title: Suspicious PowerShell Execution
description: Detects suspicious PowerShell command patterns
level: medium
detection:
    selection:
        - EventID: 4104
        - ScriptBlockText|contains:
            - 'DownloadString'
            - 'Invoke-Expression'
            - 'IEX'
            - 'Net.WebClient'
            - '-enc'
            - '-EncodedCommand'
    condition: selection
'''
        },
        {
            'name': 'mimikatz_detection',
            'title': 'Mimikatz Credential Dumping',
            'description': 'Detects potential Mimikatz credential dumping activity',
            'author': 'caseScope Team',
            'level': 'high',
            'status': 'stable',
            'category': 'process_creation',
            'tags': json.dumps(['mimikatz', 'credential-access', 'attack.t1003']),
            'rule_yaml': '''
title: Mimikatz Credential Dumping
description: Detects Mimikatz credential dumping
level: high
detection:
    selection:
        - EventID: 4688
        - CommandLine|contains:
            - 'sekurlsa'
            - 'lsadump'
            - 'privilege::debug'
    condition: selection
'''
        },
        {
            'name': 'suspicious_network_logon',
            'title': 'Suspicious Network Logon',
            'description': 'Detects suspicious network logon attempts',
            'author': 'caseScope Team',
            'level': 'medium',
            'status': 'stable',
            'category': 'authentication',
            'tags': json.dumps(['logon', 'network', 'lateral-movement']),
            'rule_yaml': '''
title: Suspicious Network Logon
description: Detects suspicious network logon patterns
level: medium
detection:
    selection:
        EventID: 4624
        LogonType: 3
    filter:
        IpAddress|startswith:
            - '10.'
            - '172.16.'
            - '192.168.'
    condition: selection and not filter
'''
        },
        {
            'name': 'defender_disabled',
            'title': 'Windows Defender Disabled',
            'description': 'Detects when Windows Defender is disabled',
            'author': 'caseScope Team',
            'level': 'high',
            'status': 'stable',
            'category': 'defense_evasion',
            'tags': json.dumps(['defender', 'evasion', 'attack.t1562']),
            'rule_yaml': '''
title: Windows Defender Disabled
description: Detects when Windows Defender real-time protection is disabled
level: high
detection:
    selection:
        EventID: 5001
    condition: selection
'''
        },
        {
            'name': 'failed_logon_attempts',
            'title': 'Multiple Failed Logon Attempts',
            'description': 'Detects multiple failed logon attempts indicating brute force',
            'author': 'caseScope Team',
            'level': 'medium',
            'status': 'stable',
            'category': 'credential_access',
            'tags': json.dumps(['bruteforce', 'failed-logon', 'attack.t1110']),
            'rule_yaml': '''
title: Multiple Failed Logon Attempts
description: Detects brute force attempts via multiple failed logons
level: medium
detection:
    selection:
        EventID: 4625
    condition: selection
'''
        }
    ]
    
    # Add each rule
    added_count = 0
    for rule_data in default_rules:
        # Calculate hash of YAML
        rule_hash = hashlib.sha256(rule_data['rule_yaml'].encode()).hexdigest()
        
        # Check if rule already exists by hash
        existing = db.session.query(SigmaRule).filter_by(rule_hash=rule_hash).first()
        if not existing:
            rule = SigmaRule(
                name=rule_data['name'],
                title=rule_data['title'],
                description=rule_data['description'],
                author=rule_data['author'],
                level=rule_data['level'],
                status=rule_data['status'],
                category=rule_data['category'],
                tags=rule_data['tags'],
                rule_yaml=rule_data['rule_yaml'],
                rule_hash=rule_hash,
                is_builtin=True,
                is_enabled=True
            )
            db.session.add(rule)
            added_count += 1
    
    if added_count > 0:
        db.session.commit()
        print(f"Loaded {added_count} default SIGMA rules")
    else:
        print("No new default SIGMA rules to load")

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        
        # Run migrations for existing databases
        try:
            from sqlalchemy import inspect, text
            inspector = inspect(db.engine)
            
            # Check case_file table migrations
            if 'case_file' in inspector.get_table_names():
                columns = [col['name'] for col in inspector.get_columns('case_file')]
                
                if 'violation_count' not in columns:
                    print("Running migration: Adding violation_count column to case_file table...")
                    db.session.execute(text('ALTER TABLE case_file ADD COLUMN violation_count INTEGER DEFAULT 0'))
                    db.session.commit()
                    print("Migration completed: violation_count column added")
                
                if 'estimated_event_count' not in columns:
                    print("Running migration: Adding estimated_event_count column to case_file table...")
                    db.session.execute(text('ALTER TABLE case_file ADD COLUMN estimated_event_count INTEGER DEFAULT 0'))
                    db.session.commit()
                    print("Migration completed: estimated_event_count column added")
                
                if 'celery_task_id' not in columns:
                    print("Running migration: Adding celery_task_id column to case_file table...")
                    db.session.execute(text('ALTER TABLE case_file ADD COLUMN celery_task_id VARCHAR(100)'))
                    db.session.commit()
                    print("Migration completed: celery_task_id column added")
        except Exception as e:
            print(f"Migration check/execution note: {e}")
            db.session.rollback()
        
        # Create default admin user
        admin = db.session.query(User).filter_by(username='administrator').first()
        if not admin:
            admin = User(
                username='administrator',
                email='admin@casescope.local',
                role='administrator',
                force_password_change=True
            )
            admin.set_password('ChangeMe!')
            db.session.add(admin)
            db.session.commit()
            print("Created default administrator user")
        
        # Load default SIGMA rules
        load_default_sigma_rules()

# File processing progress API endpoint
@app.route('/api/file/progress/<int:file_id>')
@login_required
def file_progress(file_id):
    """
    Get real-time processing progress for a file
    Returns Celery task state, progress, and status
    """
    case_file = db.session.get(CaseFile, file_id)
    if not case_file:
        return jsonify({'error': 'File not found'}), 404
    
    # Check if user has access to this file's case
    if case_file.case_id != session.get('active_case_id'):
        return jsonify({'error': 'Access denied'}), 403
    
    response = {
        'file_id': file_id,
        'filename': case_file.original_filename,
        'status': case_file.indexing_status,
        'event_count': case_file.event_count,
        'estimated_event_count': case_file.estimated_event_count or int((case_file.file_size / 1048576) * 1000),
        'violation_count': case_file.violation_count,
        'is_indexed': case_file.is_indexed
    }
    
    # If there's a Celery task ID, check its state
    if case_file.celery_task_id and celery_app:
        try:
            from celery.result import AsyncResult
            task_result = AsyncResult(case_file.celery_task_id, app=celery_app)
            
            response['celery_state'] = task_result.state
            response['task_id'] = case_file.celery_task_id
            
            # Get detailed task info based on state
            if task_result.state == 'PENDING':
                response['progress'] = 0
                response['message'] = 'Task queued, waiting to start'
            elif task_result.state == 'STARTED':
                response['progress'] = 10
                response['message'] = 'Task started'
            elif task_result.state == 'PROGRESS':
                # Get progress metadata if available
                if task_result.info:
                    response['progress'] = int((task_result.info.get('current', 0) / 
                                               max(task_result.info.get('total', 1), 1)) * 100)
                    response['message'] = task_result.info.get('status', case_file.indexing_status)
                    # Include progress metadata for different stages
                    if task_result.info.get('current'):
                        response['current'] = task_result.info.get('current', 0)
                    if task_result.info.get('total'):
                        response['total'] = task_result.info.get('total', 0)
                    if task_result.info.get('violations'):
                        response['violations_found'] = task_result.info.get('violations', 0)
                else:
                    response['progress'] = 50
                    response['message'] = case_file.indexing_status
            elif task_result.state == 'SUCCESS':
                response['progress'] = 100
                response['status'] = 'Completed'
                response['message'] = 'Completed'
                # Update DB if status doesn't match
                if case_file.indexing_status != 'Completed':
                    case_file.indexing_status = 'Completed'
                    case_file.celery_task_id = None  # Clear task ID
                    db.session.commit()
            elif task_result.state == 'FAILURE':
                response['progress'] = 0
                response['status'] = 'Failed'
                response['message'] = f'Failed: {str(task_result.info)}'
                response['error'] = str(task_result.info)
                # Update DB
                if case_file.indexing_status != 'Failed':
                    case_file.indexing_status = 'Failed'
                    case_file.celery_task_id = None
                    db.session.commit()
            else:
                # Other states (RETRY, REVOKED, etc.)
                response['progress'] = 0
                response['message'] = task_result.state
        except Exception as e:
            response['celery_error'] = str(e)
            response['celery_state'] = 'UNKNOWN'
    else:
        # No task ID - use DB status
        if case_file.indexing_status == 'Completed':
            response['progress'] = 100
            response['message'] = 'Completed'
        elif case_file.indexing_status == 'Failed':
            response['progress'] = 0
            response['message'] = 'Failed'
        elif case_file.indexing_status == 'SIGMA Hunting':
            response['progress'] = 50
            response['event_count'] = case_file.event_count or 0
            response['message'] = 'SIGMA Hunting (scanning events)'
        elif case_file.indexing_status == 'IOC Hunting':
            response['progress'] = 75
            response['message'] = 'IOC Hunting'
        else:
            response['progress'] = 0
            response['message'] = case_file.indexing_status
    
    return jsonify(response)

# Health check endpoint for diagnostics and monitoring
@app.route('/healthz')
def healthz():
    """
    Health check endpoint - verifies DB and OpenSearch connectivity
    Returns JSON with component status for troubleshooting
    """
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'version': APP_VERSION,
        'components': {}
    }
    
    # Check database connectivity
    try:
        db.session.execute(db.text('SELECT 1'))
        health_status['components']['database'] = {
            'status': 'up',
            'type': 'SQLite',
            'uri': app.config['SQLALCHEMY_DATABASE_URI']
        }
    except Exception as e:
        health_status['status'] = 'degraded'
        health_status['components']['database'] = {
            'status': 'down',
            'error': str(e)
        }
    
    # Check OpenSearch connectivity
    try:
        opensearch_client = OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            timeout=5
        )
        cluster_health = opensearch_client.cluster.health()
        health_status['components']['opensearch'] = {
            'status': 'up',
            'cluster_status': cluster_health.get('status', 'unknown'),
            'number_of_nodes': cluster_health.get('number_of_nodes', 0),
            'active_shards': cluster_health.get('active_shards', 0)
        }
    except Exception as e:
        health_status['status'] = 'degraded'
        health_status['components']['opensearch'] = {
            'status': 'down',
            'error': str(e)
        }
    
    # Check Redis connectivity (Celery broker)
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0, socket_timeout=2)
        r.ping()
        queue_length = r.llen('celery')
        health_status['components']['redis'] = {
            'status': 'up',
            'queue_length': queue_length
        }
    except Exception as e:
        health_status['status'] = 'degraded'
        health_status['components']['redis'] = {
            'status': 'down',
            'error': str(e)
        }
    
    # Check Celery worker connectivity
    try:
        if celery_app:
            # Try to get active workers
            inspect = celery_app.control.inspect(timeout=2)
            active_workers = inspect.active()
            if active_workers:
                health_status['components']['celery_worker'] = {
                    'status': 'up',
                    'workers': list(active_workers.keys()),
                    'active_tasks': sum(len(tasks) for tasks in active_workers.values())
                }
            else:
                health_status['status'] = 'degraded'
                health_status['components']['celery_worker'] = {
                    'status': 'down',
                    'error': 'No workers responding'
                }
        else:
            health_status['components']['celery_worker'] = {
                'status': 'unknown',
                'error': 'Celery not initialized'
            }
    except Exception as e:
        health_status['status'] = 'degraded'
        health_status['components']['celery_worker'] = {
            'status': 'down',
            'error': str(e)
        }
    
    # Return appropriate HTTP status code
    status_code = 200 if health_status['status'] == 'healthy' else 503
    
    return jsonify(health_status), status_code

def render_edit_case(case, users):
    """Render case edit form"""
    sidebar_menu = render_sidebar_menu('case_dashboard')
    
    # Get flash messages
    from flask import get_flashed_messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    # Build assignee options
    assignee_options = '<option value="">-- Unassigned --</option>'
    for user in users:
        selected = 'selected' if case.assignee_id == user.id else ''
        assignee_options += f'<option value="{user.id}" {selected}>{user.username}</option>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Edit Case - caseScope {APP_VERSION}</title>
        {get_theme_css()}    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                📁 caseScope
                <div class="version-badge">v{APP_VERSION}</div>
            </div>
            {sidebar_menu}
        </div>
        <div class="main-content">
            {flash_messages_html}
            <div class="form-container">
                <h2>Edit Case: {html.escape(case.name)}</h2>
                <form method="POST">
                    <div class="form-group">
                        <label for="name">Case Name *</label>
                        <input type="text" id="name" name="name" required value="{html.escape(case.name)}">
                    </div>
                    <div class="form-group">
                        <label for="description">Description</label>
                        <textarea id="description" name="description">{html.escape(case.description or '')}</textarea>
                    </div>
                    <div class="form-group">
                        <label for="company">Company/Customer Name</label>
                        <input type="text" id="company" name="company" value="{html.escape(case.company or '')}" placeholder="e.g., Acme Corporation, City Police Department">
                        <small style="color: #94a3b8; display: block; margin-top: 0.3rem;">Used for DFIR-IRIS integration (optional)</small>
                    </div>
                    <div class="form-group">
                        <label for="priority">Priority</label>
                        <select id="priority" name="priority">
                            <option value="Low" {'selected' if case.priority == 'Low' else ''}>Low</option>
                            <option value="Medium" {'selected' if case.priority == 'Medium' else ''}>Medium</option>
                            <option value="High" {'selected' if case.priority == 'High' else ''}>High</option>
                            <option value="Critical" {'selected' if case.priority == 'Critical' else ''}>Critical</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="status">Status</label>
                        <select id="status" name="status">
                            <option value="Open" {'selected' if case.status == 'Open' else ''}>Open</option>
                            <option value="In Progress" {'selected' if case.status == 'In Progress' else ''}>In Progress</option>
                            <option value="Closed" {'selected' if case.status == 'Closed' else ''}>Closed</option>
                            <option value="Archived" {'selected' if case.status == 'Archived' else ''}>Archived</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="assignee_id">Assigned To</label>
                        <select id="assignee_id" name="assignee_id">
                            {assignee_options}
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="tags">Tags (comma-separated)</label>
                        <input type="text" id="tags" name="tags" value="{html.escape(case.tags or '')}" placeholder="e.g., malware, ransomware, data-breach">
                    </div>
                    <div style="margin-top: 25px;">
                        <button type="submit">Save Changes</button>
                        <button type="button" class="cancel-btn" onclick="window.history.back()">Cancel</button>
                    </div>
                </form>
            </div>
        </div>
    </body>
    </html>
    '''

def render_case_management(cases, users):
    """Render case management page - matches files list structure"""
    from flask import get_flashed_messages
    sidebar_menu = render_sidebar_menu('case_management')
    
    # Get flash messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    # Build case rows
    case_rows = ""
    for case in cases:
        status_class = case.status.lower().replace(' ', '-')
        status_badge = f'<span class="status-{status_class}">{case.status}</span>'
        
        assignee_name = case.assignee.username if case.assignee else 'Unassigned'
        tags_display = html.escape(case.tags or 'None')
        
        # Action buttons matching files list style
        actions_list = []
        actions_list.append(f'<a href="/case/edit/{case.id}" style="text-decoration: none;"><button class="btn-action" style="background: linear-gradient(145deg, #2196f3, #1976d2);">✏️ Edit</button></a>')
        
        if case.status == 'Closed' or case.status == 'Archived':
            actions_list.append(f'<button class="btn-action" onclick="reopenCase({case.id}, \'{html.escape(case.name)}\')" style="background: linear-gradient(145deg, #4caf50, #388e3c);">↻ Reopen</button>')
        else:
            actions_list.append(f'<button class="btn-action" onclick="closeCase({case.id}, \'{html.escape(case.name)}\')" style="background: linear-gradient(145deg, #ff9800, #f57c00);">✓ Close</button>')
            actions_list.append(f'<button class="btn-action" onclick="archiveCase({case.id}, \'{html.escape(case.name)}\')" style="background: linear-gradient(145deg, #757575, #616161);">📦 Archive</button>')
        
        # Admin-only delete button
        if current_user.role == 'administrator':
            actions_list.append(f'<button class="btn-action" onclick="deleteCase({case.id}, \'{html.escape(case.name)}\')" style="background: linear-gradient(145deg, #f44336, #d32f2f);">🗑️ Delete</button>')
        
        actions = '<div style="display: flex; flex-wrap: wrap; gap: 4px;">' + ''.join(actions_list) + '</div>'
        
        case_rows += f'''
        <tr>
            <td><a href="/case/set/{case.id}" style="color: white; text-decoration: underline;">{html.escape(case.case_number)}</a></td>
            <td>{html.escape(case.name)}</td>
            <td><span class="priority-{case.priority.lower()}">{case.priority}</span></td>
            <td>{status_badge}</td>
            <td>{assignee_name}</td>
            <td>{tags_display}</td>
            <td>{case.file_count}</td>
            <td>{case.created_at.strftime('%Y-%m-%d')}</td>
            <td>{actions}</td>
        </tr>
        '''
    
    if not case_rows:
        case_rows = '<tr><td colspan="9" style="text-align: center; padding: 40px;">No cases found. <a href="/case/create" style="color: white;">Create your first case</a>.</td></tr>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Case Management - caseScope {APP_VERSION}</title>
        {get_theme_css()}    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            {sidebar_menu}
        </div>
        <div class="main-content">
            <div class="header">
                <div class="case-title">⚙️ Case Management</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                <h1>⚙️ Case Management</h1>
                <p>Manage all cases - edit details, assign users, close or archive cases.</p>
                
                {flash_messages_html}
                
                <table class="file-table">
                    <thead>
                        <tr>
                            <th>Case Number</th>
                            <th>Name</th>
                            <th>Priority</th>
                            <th>Status</th>
                            <th>Assigned To</th>
                            <th>Tags</th>
                            <th>Files</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {case_rows}
                    </tbody>
                </table>
            </div>
        </div>
        
        <script>
            function closeCase(id, name) {{
                if (confirm('Close case "' + name + '"?')) {{
                    fetch('/case/close/' + id, {{
                        method: 'POST'
                    }})
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) {{
                            location.reload();
                        }} else {{
                            alert('Error: ' + data.message);
                        }}
                    }})
                    .catch(error => {{
                        alert('Error: ' + error);
                    }});
                }}
            }}
            
            function archiveCase(id, name) {{
                if (confirm('Archive case "' + name + '"? This will hide it from active cases.')) {{
                    fetch('/case/archive/' + id, {{
                        method: 'POST'
                    }})
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) {{
                            location.reload();
                        }} else {{
                            alert('Error: ' + data.message);
                        }}
                    }})
                    .catch(error => {{
                        alert('Error: ' + error);
                    }});
                }}
            }}
            
            function reopenCase(id, name) {{
                if (confirm('Reopen case "' + name + '"?')) {{
                    fetch('/case/reopen/' + id, {{
                        method: 'POST'
                    }})
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) {{
                            location.reload();
                        }} else {{
                            alert('Error: ' + data.message);
                        }}
                    }})
                    .catch(error => {{
                        alert('Error: ' + error);
                    }});
                }}
            }}
            
            function deleteCase(id, name) {{
                if (confirm('⚠️ WARNING: PERMANENTLY DELETE case "' + name + '"?\\n\\nThis will DELETE ALL:\\n• Uploaded files\\n• OpenSearch indices\\n• IOCs and matches\\n• SIGMA violations\\n• Search history\\n• Event tags\\n\\nThis action CANNOT be undone!')) {{
                    if (confirm('Are you ABSOLUTELY SURE you want to delete "' + name + '" forever?\\n\\nType the case name in the next prompt to confirm.')) {{
                        const confirmName = prompt('Type the case name to confirm deletion:\\n"' + name + '"');
                        if (confirmName === name) {{
                            fetch('/case/delete/' + id, {{
                                method: 'POST'
                            }})
                            .then(response => response.json())
                            .then(data => {{
                                if (data.success) {{
                                    alert('✓ Case deleted successfully');
                                    window.location.href = '/case-management';
                                }} else {{
                                    alert('Error: ' + data.message);
                                }}
                            }})
                            .catch(error => {{
                                alert('Error: ' + error);
                            }});
                        }} else {{
                            alert('Case name did not match. Deletion cancelled.');
                        }}
                    }}
                }}
            }}
        </script>
    </body>
    </html>
    '''

def render_file_management(files, cases):
    """Render file management page - matches files list structure"""
    from flask import get_flashed_messages
    sidebar_menu = render_sidebar_menu('file_management')
    
    # Get flash messages
    flash_messages_html = ""
    messages = get_flashed_messages(with_categories=True)
    for category, message in messages:
        icon = "⚠️" if category == "warning" else "❌" if category == "error" else "✅"
        flash_messages_html += f'''
        <div class="flash-message flash-{category}">
            <span class="flash-icon">{icon}</span>
            <span class="flash-text">{message}</span>
            <button class="flash-close" onclick="this.parentElement.remove()">×</button>
        </div>
        '''
    
    # Get IOC match counts for all files
    from sqlalchemy import func
    ioc_counts = {}
    if files:
        # IOCMatch uses source_filename, not file_id, so we need to join with CaseFile
        file_ids = [f.id for f in files]
        ioc_count_results = db.session.query(
            CaseFile.id.label('file_id'),
            func.count(func.distinct(IOCMatch.event_id)).label('ioc_count')
        ).join(
            IOCMatch, 
            (IOCMatch.source_filename == CaseFile.original_filename) & 
            (IOCMatch.case_id == CaseFile.case_id)
        ).filter(
            CaseFile.id.in_(file_ids),
            CaseFile.is_deleted == False
        ).group_by(CaseFile.id).all()
        
        for file_id, count in ioc_count_results:
            ioc_counts[file_id] = count
    
    # Build file rows
    file_rows = ""
    for file in files:
        file_size_mb = file.file_size / (1024 * 1024)
        status_class = file.indexing_status.lower().replace(' ', '-')
        
        # Status display with color coding
        # STATUS COLORS: Queued=#9ca3af, Indexing=#ff9800, SIGMA=#fbbf24, IOC=#60a5fa, Complete=#4caf50, Failed=#f44336
        if file.indexing_status == 'Queued':
            status_display = '<div class="status-text" style="color: #9ca3af;">Queued</div>'
            status_class = 'queued'
        elif file.indexing_status == 'Estimating':
            status_display = '<div class="status-text" style="color: #9ca3af;">Estimating...</div>'
            status_class = 'estimating'
        elif file.indexing_status == 'Indexing':
            current_events = file.event_count or 0
            estimated = file.estimated_event_count or int((file.file_size / 1048576) * 1000)
            status_display = f'<div class="status-text" style="color: #ff9800;">Indexing... ({current_events:,} / {estimated:,} events)</div>'
            status_class = 'indexing'
        elif file.indexing_status == 'SIGMA Hunting':
            status_display = '<div class="status-text" style="color: #fbbf24;">SIGMA Hunting...</div>'
            status_class = 'sigma-hunting'
        elif file.indexing_status == 'IOC Hunting':
            status_display = '<div class="status-text" style="color: #60a5fa;">IOC Hunting...</div>'
            status_class = 'ioc-hunting'
        elif file.indexing_status == 'Completed':
            status_display = '<div class="status-text" style="color: #4caf50;">Completed</div>'
            status_class = 'completed'
        elif file.indexing_status == 'Failed':
            status_display = '<div class="status-text" style="color: #f44336;">Failed</div>'
            status_class = 'failed'
        else:
            status_display = f'<div class="status-text">{file.indexing_status}</div>'
        
        # Event and violation counts
        events_display = f'{file.event_count:,}' if file.event_count and file.event_count > 0 else '-'
        violations_display = f'{file.violation_count:,}' if file.violation_count and file.violation_count > 0 else '-'
        
        # IOC match count
        ioc_count = ioc_counts.get(file.id, 0)
        iocs_display = f'{ioc_count:,}' if ioc_count > 0 else '-'
        
        # Action buttons
        actions_list = []
        actions_list.append(f'<button class="btn-action" onclick="reindexFile({file.id})" style="background: linear-gradient(145deg, #2196f3, #1976d2);">🔄 Re-index</button>')
        
        if file.is_indexed and file.indexing_status in ['SIGMA Hunting', 'IOC Hunting', 'Completed', 'Failed']:
            actions_list.append(f'<button class="btn-action" onclick="rerunRules({file.id})" style="background: linear-gradient(145deg, #ff9800, #f57c00);">⚡ Re-run Rules</button>')
        
        if current_user.role == 'administrator':
            actions_list.append(f'<button class="btn-action" onclick="deleteFile({file.id}, \'{html.escape(file.original_filename)}\')" style="background: linear-gradient(145deg, #f44336, #d32f2f);">🗑️ Delete</button>')
        
        actions = '<div style="display: flex; flex-wrap: wrap; gap: 4px;">' + ''.join(actions_list) + '</div>'
        
        file_rows += f'''
        <tr data-case-id="{file.case_id}" data-status="{file.indexing_status}" data-filename="{html.escape(file.original_filename).lower()}">
            <td><input type="checkbox" class="file-checkbox" value="{file.id}"></td>
            <td>{html.escape(file.original_filename)}</td>
            <td><a href="/case/set/{file.case_id}" style="color: white; text-decoration: underline;">{html.escape(file.case.name)}</a></td>
            <td>{file.uploaded_at.strftime('%Y-%m-%d %H:%M')}</td>
            <td>{file_size_mb:.2f} MB</td>
            <td>{file.uploader.username}</td>
            <td><span class="status-{status_class}">{status_display}</span></td>
            <td>{events_display}</td>
            <td>{violations_display}</td>
            <td>{iocs_display}</td>
            <td>{actions}</td>
        </tr>
        '''
    
    if not file_rows:
        file_rows = '<tr><td colspan="11" style="text-align: center; padding: 40px;">No files found.</td></tr>'
    
    # Build case filter options
    case_options = '<option value="">All Cases</option>'
    for case in cases:
        case_options += f'<option value="{case.id}">{html.escape(case.name)}</option>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>File Management - caseScope {APP_VERSION}</title>
        {get_theme_css()}    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            {sidebar_menu}
        </div>
        <div class="main-content">
            <div class="header">
                <div class="case-title">🗂️ File Management</div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                <h1>🗂️ File Management</h1>
                <p>Manage all files across all cases - filter, search, and perform bulk actions.</p>
                
                {flash_messages_html}
                
                <div class="filter-box">
                    <input type="text" id="searchBox" placeholder="Search filename..." onkeyup="filterFiles()">
                    <select id="caseFilter" onchange="filterFiles()">
                        {case_options}
                    </select>
                    <select id="statusFilter" onchange="filterFiles()">
                        <option value="">All Statuses</option>
                        <option value="Queued">Queued</option>
                        <option value="Estimating">Estimating</option>
                        <option value="Indexing">Indexing</option>
                        <option value="SIGMA Hunting">SIGMA Hunting</option>
                        <option value="IOC Hunting">IOC Hunting</option>
                        <option value="Completed">Completed</option>
                        <option value="Failed">Failed</option>
                    </select>
                    <button onclick="clearFilters()" class="bulk-btn" style="background: linear-gradient(145deg, #757575, #616161);">Clear Filters</button>
                </div>
                
                <div class="bulk-actions">
                    <label style="display: flex; align-items: center; gap: 8px;">
                        <input type="checkbox" id="selectAll" onchange="toggleSelectAll()">
                        <span>Select All</span>
                    </label>
                    <button id="bulkReindex" class="bulk-btn" style="background: linear-gradient(145deg, #2196f3, #1976d2);" onclick="bulkReindex()" disabled>🔄 Re-index Selected</button>
                    <button id="bulkRerun" class="bulk-btn" style="background: linear-gradient(145deg, #ff9800, #f57c00);" onclick="bulkRerunRules()" disabled>⚡ Re-run Rules on Selected</button>
                    {"<button id='bulkDelete' class='bulk-btn' style='background: linear-gradient(145deg, #f44336, #d32f2f);' onclick='bulkDelete()' disabled>🗑️ Delete Selected</button>" if current_user.role == 'administrator' else ""}
                </div>
                
                <table class="file-table" id="fileTable">
                    <thead>
                        <tr>
                            <th style="width: 40px;">Select</th>
                            <th>Filename</th>
                            <th>Case</th>
                            <th>Uploaded</th>
                            <th>Size</th>
                            <th>Uploader</th>
                            <th>Status</th>
                            <th>Events</th>
                            <th>Violations</th>
                            <th>IOCs</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {file_rows}
                    </tbody>
                </table>
            </div>
        </div>
        
        <script>
            function filterFiles() {{
                const searchText = document.getElementById('searchBox').value.toLowerCase();
                const caseFilter = document.getElementById('caseFilter').value;
                const statusFilter = document.getElementById('statusFilter').value;
                const rows = document.querySelectorAll('#fileTable tbody tr');
                
                rows.forEach(row => {{
                    if (row.cells.length === 1) return; // Skip empty message row
                    
                    const filename = row.getAttribute('data-filename') || '';
                    const caseId = row.getAttribute('data-case-id') || '';
                    const status = row.getAttribute('data-status') || '';
                    
                    const matchesSearch = filename.includes(searchText);
                    const matchesCase = !caseFilter || caseId === caseFilter;
                    const matchesStatus = !statusFilter || status === statusFilter;
                    
                    row.style.display = (matchesSearch && matchesCase && matchesStatus) ? '' : 'none';
                }});
            }}
            
            function clearFilters() {{
                document.getElementById('searchBox').value = '';
                document.getElementById('caseFilter').value = '';
                document.getElementById('statusFilter').value = '';
                filterFiles();
            }}
            
            function toggleSelectAll() {{
                const selectAll = document.getElementById('selectAll').checked;
                document.querySelectorAll('.file-checkbox').forEach(cb => {{
                    if (cb.closest('tr').style.display !== 'none') {{
                        cb.checked = selectAll;
                    }}
                }});
                updateBulkButtons();
            }}
            
            function updateBulkButtons() {{
                const selected = document.querySelectorAll('.file-checkbox:checked').length;
                document.getElementById('bulkReindex').disabled = selected === 0;
                document.getElementById('bulkRerun').disabled = selected === 0;
                const bulkDelete = document.getElementById('bulkDelete');
                if (bulkDelete) bulkDelete.disabled = selected === 0;
            }}
            
            document.querySelectorAll('.file-checkbox').forEach(cb => {{
                cb.addEventListener('change', updateBulkButtons);
            }});
            
            function getSelectedIds() {{
                return Array.from(document.querySelectorAll('.file-checkbox:checked')).map(cb => cb.value);
            }}
            
            function bulkReindex() {{
                const ids = getSelectedIds();
                if (ids.length === 0) return;
                
                if (confirm(`Re-index ${{ids.length}} file(s)? This will discard existing indexes.`)) {{
                    ids.forEach(id => reindexFile(id));
                }}
            }}
            
            function bulkRerunRules() {{
                const ids = getSelectedIds();
                if (ids.length === 0) return;
                
                if (confirm(`Re-run SIGMA rules on ${{ids.length}} file(s)?`)) {{
                    ids.forEach(id => rerunRules(id));
                }}
            }}
            
            function bulkDelete() {{
                const ids = getSelectedIds();
                if (ids.length === 0) return;
                
                if (confirm(`DELETE ${{ids.length}} file(s)? This cannot be undone.`)) {{
                    ids.forEach(id => {{
                        fetch('/file/delete/' + id, {{ method: 'POST' }})
                        .then(response => response.json())
                        .then(data => {{
                            if (data.success) location.reload();
                            else alert('Error deleting file: ' + data.message);
                        }});
                    }});
                }}
            }}
            
            function reindexFile(id) {{
                fetch('/file/reindex/' + id, {{ method: 'POST' }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) location.reload();
                    else alert('Error: ' + data.message);
                }});
            }}
            
            function rerunRules(id) {{
                fetch('/file/rerun-rules/' + id, {{ method: 'POST' }})
                .then(response => response.json())
                .then(data => {{
                    if (data.success) location.reload();
                    else alert('Error: ' + data.message);
                }});
            }}
            
            function deleteFile(id, filename) {{
                if (confirm('Delete "' + filename + '"? This cannot be undone.')) {{
                    fetch('/file/delete/' + id, {{ method: 'POST' }})
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success) location.reload();
                        else alert('Error: ' + data.message);
                    }});
                }}
            }}
        </script>
    </body>
    </html>
    '''

# ============================================================================
# TIMELINE TAGGING API ENDPOINTS
# ============================================================================

@app.route('/api/event/tag', methods=['POST'])
@login_required
def tag_event():
    """
    Tag an event for timeline inclusion
    Expects JSON: {event_id, index_name, event_timestamp, tag_type, color, notes}
    """
    try:
        data = request.get_json()
        
        if not data or 'event_id' not in data or 'index_name' not in data:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Get active case
        case_id = session.get('active_case_id')
        if not case_id:
            return jsonify({'success': False, 'message': 'No active case'}), 400
        
        # Check if already tagged by this user for this tag_type
        tag_type = data.get('tag_type', 'timeline')
        existing = db.session.execute(
            select(EventTag).where(
                EventTag.case_id == case_id,
                EventTag.event_id == data['event_id'],
                EventTag.tagged_by == current_user.id,
                EventTag.tag_type == tag_type
            )
        ).scalar_one_or_none()
        
        if existing:
            return jsonify({'success': False, 'message': 'Event already tagged'}), 400
        
        # Create new tag
        tag = EventTag(
            case_id=case_id,
            event_id=data['event_id'],
            index_name=data['index_name'],
            event_timestamp=data.get('event_timestamp'),
            tag_type=tag_type,
            color=data.get('color', 'blue'),
            notes=data.get('notes'),
            tagged_by=current_user.id
        )
        
        db.session.add(tag)
        db.session.commit()
        
        # Log the action
        log_audit(
            action='tag_event',
            category='search',
            details=f'Tagged event {data["event_id"][:16]} for timeline in case {case_id}',
            success=True
        )
        
        # Auto-sync to DFIR-IRIS if enabled
        try:
            settings = db.session.query(SystemSettings).first()
            if settings and settings.iris_enabled and settings.iris_auto_sync:
                # Trigger async sync (fire and forget)
                from iris_sync import sync_case_to_iris
                import threading
                sync_thread = threading.Thread(target=sync_case_to_iris, args=(case_id,), daemon=True)
                sync_thread.start()
                print(f"[Auto-Sync] Event tagged - triggered DFIR-IRIS sync for case {case_id}")
        except Exception as e:
            # Don't fail the tagging if auto-sync fails
            print(f"[Auto-Sync] Failed to trigger sync after event tag: {e}")
        
        return jsonify({
            'success': True,
            'message': 'Event tagged for timeline',
            'tag_id': tag.id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/event/untag', methods=['POST'])
@login_required
def untag_event():
    """
    Remove a tag from an event
    Expects JSON: {event_id, tag_type}
    """
    try:
        data = request.get_json()
        
        if not data or 'event_id' not in data:
            return jsonify({'success': False, 'message': 'Missing event_id'}), 400
        
        # Get active case
        case_id = session.get('active_case_id')
        if not case_id:
            return jsonify({'success': False, 'message': 'No active case'}), 400
        
        # Find and delete the tag
        tag_type = data.get('tag_type', 'timeline')
        tag = db.session.execute(
            select(EventTag).where(
                EventTag.case_id == case_id,
                EventTag.event_id == data['event_id'],
                EventTag.tagged_by == current_user.id,
                EventTag.tag_type == tag_type
            )
        ).scalar_one_or_none()
        
        if not tag:
            return jsonify({'success': False, 'message': 'Tag not found'}), 404
        
        db.session.delete(tag)
        db.session.commit()
        
        # Log the action
        log_audit(
            action='untag_event',
            category='search',
            details=f'Removed timeline tag from event {data["event_id"][:16]} in case {case_id}',
            success=True
        )
        
        return jsonify({
            'success': True,
            'message': 'Event tag removed'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/event/tags')
@login_required
def get_event_tags():
    """
    Get all tagged events for the active case
    Returns list of event_ids that are tagged
    """
    try:
        # Get active case
        case_id = session.get('active_case_id')
        if not case_id:
            return jsonify({'success': False, 'message': 'No active case'}), 400
        
        # Get tag_type filter (optional)
        tag_type = request.args.get('tag_type', 'timeline')
        
        # Get all tags for this case
        tags = db.session.execute(
            select(EventTag).where(
                EventTag.case_id == case_id,
                EventTag.tag_type == tag_type
            )
        ).scalars().all()
        
        # Return as dictionary keyed by event_id for easy lookup
        tagged_events = {}
        for tag in tags:
            if tag.event_id not in tagged_events:
                tagged_events[tag.event_id] = []
            tagged_events[tag.event_id].append({
                'tag_id': tag.id,
                'tagged_by': tag.tagged_by,
                'tagged_by_username': tag.tagger.username if tag.tagger else 'Unknown',
                'tagged_at': tag.tagged_at.isoformat() if tag.tagged_at else None,
                'tag_type': tag.tag_type,
                'color': tag.color,
                'notes': tag.notes
            })
        
        return jsonify({
            'success': True,
            'tagged_events': tagged_events,
            'total_tags': len(tags)
        }), 200
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    print("Starting caseScope 7.1 application...")
    print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print("Initializing database...")
    init_db()
    print("Database initialization completed")
    print("Starting Flask application on 0.0.0.0:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
