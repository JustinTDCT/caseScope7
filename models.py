#!/usr/bin/env python3
"""
caseScope 9.0.0 - Database Models
Copyright (c) 2025 Justin Dube <casescope@thedubes.net>

All SQLAlchemy database models for caseScope application.
"""

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import bcrypt

# Database instance (will be initialized by main.py)
db = SQLAlchemy()


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
    
    # Aggregate Statistics (v9.4.0 - cached from CaseFile for performance)
    total_files = db.Column(db.Integer, default=0)
    total_events = db.Column(db.BigInteger, default=0)
    total_events_with_iocs = db.Column(db.Integer, default=0)
    total_events_with_sigma = db.Column(db.Integer, default=0)
    
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
    is_hidden = db.Column(db.Boolean, default=False)  # Hide from file lists and searches
    event_count = db.Column(db.Integer, default=0)
    estimated_event_count = db.Column(db.Integer, default=0)  # Estimated total events for progress
    violation_count = db.Column(db.Integer, default=0)
    indexing_status = db.Column(db.String(20), default='Queued')  # Queued, Estimating, Indexing, SIGMA Hunting, IOC Hunting, Completed, Failed
    celery_task_id = db.Column(db.String(100), nullable=True)  # Current Celery task ID for progress tracking
    
    # v9.4.0 - Statistics and Linking
    ioc_event_count = db.Column(db.Integer, default=0)  # Number of events with IOC matches
    sigma_event_count = db.Column(db.Integer, default=0)  # Number of events with SIGMA violations
    upload_type = db.Column(db.String(50), default='http')  # 'http' or 'local'
    opensearch_key = db.Column(db.String(255), index=True)  # 'case{id}_{filename}' for DB<->OpenSearch linking
    is_tagged = db.Column(db.Boolean, default=False)  # If file has any tagged events
    
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


class SkippedFile(db.Model):
    """
    Audit log of files that were skipped during upload/processing.
    Provides complete forensic trail of what was uploaded and why it wasn't processed.
    
    Skip reasons:
    - duplicate_hash: File with same SHA256 hash already exists in case
    - zero_bytes: File is 0 bytes (corrupt/empty)
    - zero_events: EVTX file has 0 events after evtx_dump conversion
    - corrupt: File couldn't be opened/processed
    """
    __tablename__ = 'skipped_file'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    filename = db.Column(db.String(500), nullable=False)  # Original or prefixed filename
    file_size = db.Column(db.BigInteger, nullable=False)  # Size in bytes
    file_hash = db.Column(db.String(64))  # SHA256 hash (if calculated)
    skip_reason = db.Column(db.String(50), nullable=False)  # duplicate_hash, zero_bytes, zero_events, corrupt
    skip_details = db.Column(db.Text)  # Additional details (e.g., "Duplicate of file_id 123")
    upload_type = db.Column(db.String(20), default='local')  # 'local' or 'http'
    skipped_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    case = db.relationship('Case', backref='skipped_files')
    
    def __repr__(self):
        return f'<SkippedFile {self.filename} ({self.skip_reason})>'

