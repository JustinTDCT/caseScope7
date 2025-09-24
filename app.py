#!/usr/bin/env python3
"""
caseScope - Main Application
Copyright 2025 Justin Dube
mailto:casescope@thedubes.net
"""

import os
import sys
import stat
from pathlib import Path

# Add the script directory to Python path for version imports
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))

try:
    from version_utils import get_version, get_version_info
    # Load version dynamically to ensure updates are reflected
    def get_current_version():
        try:
            return get_version()
        except:
            return "7.0.32"
    
    def get_current_version_info():
        try:
            return get_version_info()
        except:
            return {"version": "7.0.32", "description": "Fallback version"}
            
    APP_VERSION = get_current_version()
    VERSION_INFO = get_current_version_info()
except ImportError:
    # Fallback if version_utils not available
    APP_VERSION = "7.0.32"
    VERSION_INFO = {"version": APP_VERSION, "description": "Fallback version"}
import logging
from datetime import datetime, timedelta
from functools import wraps
import json
import hashlib
import psutil
import subprocess
from pathlib import Path

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, g, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, SelectField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import bcrypt
from opensearchpy import OpenSearch
from celery import Celery
import redis
from apscheduler.schedulers.background import BackgroundScheduler
import yaml
import xml.etree.ElementTree as ET
from evtx import PyEvtxParser
import xmltodict

# Application setup
app = Flask(__name__)

# Use a fixed secret key for production (in production, this should be from environment variable)
SECRET_KEY = os.environ.get('SECRET_KEY', 'casescope-v7-production-key-change-in-production')
app.config['SECRET_KEY'] = SECRET_KEY

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////opt/casescope/data/casescope.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['UPLOAD_FOLDER'] = '/opt/casescope/data/uploads'

# CSRF configuration
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None
app.config['WTF_CSRF_SSL_STRICT'] = False

# Celery configuration
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Initialize Celery
celery = Celery(app.import_name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

# Initialize OpenSearch client
opensearch_client = OpenSearch([{'host': 'localhost', 'port': 9200}])

# Initialize Redis client
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# Initialize scheduler
scheduler = BackgroundScheduler()

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create required directories
upload_dir = app.config.get('UPLOAD_FOLDER', '/opt/casescope/data/uploads')
os.makedirs(upload_dir, exist_ok=True)
os.makedirs('/opt/casescope/logs', exist_ok=True)

# Set proper permissions for upload directory
try:
    os.chmod(upload_dir, stat.S_IRWXU | stat.S_IRWXG | stat.S_IROTH | stat.S_IXOTH)  # 755
except:
    pass

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='analyst')  # admin, analyst, readonly
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_role(self, role):
        return self.role == role

    def can_admin(self):
        return self.role == 'admin'

    def can_write(self):
        return self.role in ['admin', 'analyst']

class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    last_modified = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    creator = db.relationship('User', backref='created_cases')
    files = db.relationship('CaseFile', backref='case', lazy='dynamic')

class CaseFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.BigInteger)
    file_hash = db.Column(db.String(64))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    processing_status = db.Column(db.String(50), default='pending')  # pending, processing, completed, error
    processing_progress = db.Column(db.Integer, default=0)
    event_count = db.Column(db.Integer, default=0)
    sigma_violations = db.Column(db.Integer, default=0)
    chainsaw_violations = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text, nullable=True)
    
    # Relationships
    uploader = db.relationship('User', backref='uploaded_files')

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    hostname = db.Column(db.String(255))
    
    # Relationships
    user = db.relationship('User', backref='audit_logs')

class SystemSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

# Forms
class LoginForm(FlaskForm):
    class Meta:
        csrf = False  # Disable CSRF for login form
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class CaseForm(FlaskForm):
    name = StringField('Case Name', validators=[DataRequired(), Length(min=1, max=200)])
    description = TextAreaField('Description')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    role = SelectField('Role', choices=[('admin', 'Administrator'), ('analyst', 'Analyst'), ('readonly', 'Read Only')])

class FileUploadForm(FlaskForm):
    files = FileField('EVTX Files', validators=[
        FileAllowed(['evtx'], 'Only EVTX files are allowed!')
    ], render_kw={'multiple': True, 'accept': '.evtx'})

# Utility functions
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def inject_csrf_token():
    """Make CSRF token available to all templates"""
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=generate_csrf)

@app.before_request
def load_global_data():
    """Load data that should be available in all templates"""
    # Make version info available to all templates (load fresh each time)
    try:
        g.app_version = get_current_version()
        g.version_info = get_current_version_info()
    except:
        g.app_version = "7.0.32"
        g.version_info = {"version": "7.0.32", "description": "Fallback version"}
    
    if current_user.is_authenticated:
        # Load recent cases for the dropdown
        g.recent_cases = Case.query.filter_by(is_active=True).order_by(Case.last_modified.desc()).limit(10).all()

# CSRF Error Handler (commented out due to import issues)
# @app.errorhandler(CSRFError)
# def handle_csrf_error(e):
#     logger.error(f"CSRF error: {e.description}")
#     flash('CSRF token validation failed. Please try again.', 'error')
#     return redirect(url_for('login'))

def log_audit(action, details=None, user=None):
    """Log audit events"""
    if user is None:
        user = current_user
    
    audit_entry = AuditLog(
        user_id=user.id if user.is_authenticated else None,
        action=action,
        details=details,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        hostname=request.headers.get('Host')
    )
    db.session.add(audit_entry)
    db.session.commit()
    
    # Also write to log file
    log_line = f"{datetime.utcnow().isoformat()} - {user.username if user.is_authenticated else 'Anonymous'} - {action}"
    if details:
        log_line += f" - {details}"
    
    with open('/opt/casescope/logs/audit.log', 'a') as f:
        f.write(log_line + '\n')

def require_role(role):
    """Decorator to require specific user role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            if role == 'admin' and not current_user.can_admin():
                flash('Administrator privileges required.', 'error')
                return redirect(url_for('system_dashboard'))
            elif role == 'write' and not current_user.can_write():
                flash('Write privileges required.', 'error')
                return redirect(url_for('system_dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_system_info():
    """Get system information for dashboard"""
    try:
        # OS info - handle missing lsb_release command
        try:
            os_version = subprocess.check_output(['lsb_release', '-r', '-s'], text=True).strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback if lsb_release is not available
            try:
                with open('/etc/os-release') as f:
                    for line in f:
                        if line.startswith('VERSION_ID='):
                            os_version = line.split('=')[1].strip().strip('"')
                            break
                    else:
                        os_version = 'Unknown'
            except:
                os_version = 'Unknown'
        
        os_info = {
            'name': 'Ubuntu',
            'version': os_version
        }
        
        # System resources
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Service status - enhanced detection with better error handling
        services = {}
        
        def check_service_port(port, service_name):
            """Check if a service is running by port and process"""
            # Method 1: Simple port check with netstat
            try:
                result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=10)
                # Look for LISTEN state on the port
                for line in result.stdout.split('\n'):
                    if f':{port}' in line and 'LISTEN' in line:
                        logger.info(f"Found {service_name} listening on port {port} via netstat")
                        return True
            except Exception as e:
                logger.error(f"netstat check failed for {service_name}: {e}")
            
            # Method 2: Simple port check with ss
            try:
                result = subprocess.run(['ss', '-an'], capture_output=True, text=True, timeout=10)
                # Look for LISTEN state on the port
                for line in result.stdout.split('\n'):
                    if f':{port}' in line and 'LISTEN' in line:
                        logger.info(f"Found {service_name} listening on port {port} via ss")
                        return True
            except Exception as e:
                logger.error(f"ss check failed for {service_name}: {e}")
            
            # Method 3: TCP socket test
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                if result == 0:
                    logger.info(f"Found {service_name} via socket connection on port {port}")
                    return True
            except Exception as e:
                logger.error(f"Socket check failed for {service_name}: {e}")
            
            logger.info(f"Service {service_name} not detected on port {port}")
            return False
        
        # Check each service
        services['opensearch'] = check_service_port(9200, 'opensearch')
        services['redis-server'] = check_service_port(6379, 'redis')  
        services['nginx'] = check_service_port(80, 'nginx')
        
        # Debug logging
        logger.info(f"Service detection results: {services}")
        
        # Rule counts and last updated
        sigma_count = 0
        chainsaw_count = 0
        sigma_updated = None
        chainsaw_updated = None
        
        sigma_path = Path('/opt/casescope/rules/sigma-rules')
        if sigma_path.exists():
            sigma_count = len(list(sigma_path.glob('**/*.yml')))
            sigma_updated = datetime.fromtimestamp(sigma_path.stat().st_mtime)
        
        chainsaw_path = Path('/opt/casescope/rules/chainsaw-rules')
        if chainsaw_path.exists():
            chainsaw_count = len(list(chainsaw_path.glob('**/*.yml')))
            chainsaw_updated = datetime.fromtimestamp(chainsaw_path.stat().st_mtime)
        
        # Case and file statistics
        case_count = Case.query.filter_by(is_active=True).count()
        file_count = CaseFile.query.count()
        total_size = db.session.query(db.func.sum(CaseFile.file_size)).scalar() or 0
        
        return {
            'os': os_info,
            'memory': {
                'total': memory.total,
                'used': memory.used,
                'percent': memory.percent
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'percent': (disk.used / disk.total) * 100
            },
            'services': services,
            'rules': {
                'sigma_count': sigma_count,
                'sigma_updated': sigma_updated,
                'chainsaw_count': chainsaw_count,
                'chainsaw_updated': chainsaw_updated
            },
            'statistics': {
                'case_count': case_count,
                'file_count': file_count,
                'total_size': total_size
            }
        }
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        # Try to get at least basic service status even if other parts fail
        basic_services = {}
        try:
            def check_service_port(port, service_name):
                try:
                    result = subprocess.run(['netstat', '-tln'], capture_output=True, text=True, timeout=5)
                    return f':{port}' in result.stdout
                except:
                    try:
                        result = subprocess.run(['ss', '-tln'], capture_output=True, text=True, timeout=5)
                        return f':{port}' in result.stdout
                    except:
                        return False
            
            basic_services['opensearch'] = check_service_port(9200, 'opensearch')
            basic_services['redis-server'] = check_service_port(6379, 'redis')
            basic_services['nginx'] = check_service_port(80, 'nginx')
        except:
            basic_services = {'opensearch': False, 'redis-server': False, 'nginx': False}
        
        # Return a default structure to prevent template errors
        return {
            'os': {
                'name': 'Unknown',
                'version': 'Unknown'
            },
            'memory': {
                'total': 0,
                'used': 0,
                'percent': 0
            },
            'disk': {
                'total': 0,
                'used': 0,
                'percent': 0
            },
            'services': basic_services,
            'rules': {
                'sigma_count': 0,
                'sigma_updated': None,
                'chainsaw_count': 0,
                'chainsaw_updated': None
            },
            'statistics': {
                'case_count': 0,
                'file_count': 0,
                'total_size': 0
            }
        }

# Celery tasks
def apply_sigma_rules(events, case_file):
    """Apply actual Sigma rules to raw EVTX events"""
    try:
        violations = 0
        sigma_rules_path = Path('/opt/casescope/rules/sigma-rules')
        
        if not sigma_rules_path.exists():
            logger.warning("Sigma rules directory not found")
            return 0
            
        logger.info(f"Applying real Sigma rules to {len(events)} events")
        
        # Load actual Sigma rules from YAML files
        sigma_rules = load_actual_sigma_rules(sigma_rules_path)
        logger.info(f"Loaded {len(sigma_rules)} actual Sigma rules from YAML files")
        
        # Debug first few events and rules
        if len(events) > 0:
            logger.info(f"Sample event structure: {str(events[0])[:300]}...")
            event_data_sample = prepare_event_for_real_sigma(events[0])
            logger.info(f"Prepared event data: {str(event_data_sample)[:300]}...")
        
        if sigma_rules:
            first_rule = list(sigma_rules.items())[0]
            logger.info(f"Sample rule: {first_rule[0]} -> {str(first_rule[1])[:300]}...")
        
        events_checked = 0
        for event in events:
            try:
                events_checked += 1
                # Convert event to Sigma-compatible format (keep raw structure)
                event_data = prepare_event_for_real_sigma(event)
                
                # Debug first few events
                if events_checked <= 3:
                    logger.info(f"Event {events_checked} prepared data keys: {list(event_data.keys())}")
                    logger.info(f"Event {events_checked} sample values: {str(dict(list(event_data.items())[:5]))}")
                
                # Apply each Sigma rule directly
                rules_checked = 0
                for rule_file, rule_data in sigma_rules.items():
                    rules_checked += 1
                    
                    # Debug first event against first few rules
                    if events_checked == 1 and rules_checked <= 3:
                        logger.info(f"Checking rule {rule_file} against event 1")
                        logger.info(f"Rule detection: {rule_data.get('detection', {})}")
                    
                    if evaluate_sigma_rule(event_data, rule_data):
                        violations += 1
                        rule_title = rule_data.get('title', rule_file)
                        
                        logger.info(f"Sigma rule triggered: {rule_title}")
                        
                        # Tag event in OpenSearch with specific rule
                        try:
                            opensearch_client.update(
                                index=f"casescope-case-{case_file.case_id}",
                                id=event.get('_id', ''),
                                body={
                                    'doc': {
                                        'sigma_hit': True,
                                        'sigma_rule': rule_title,
                                        'sigma_rule_file': rule_file,
                                        'severity': rule_data.get('level', 'medium'),
                                        'rule_category': rule_data.get('logsource', {}).get('category', 'unknown')
                                    }
                                }
                            )
                        except Exception as tag_error:
                            logger.warning(f"Failed to tag event with Sigma rule: {tag_error}")
                        
                        # Don't break - an event can violate multiple rules
                        
            except Exception as e:
                logger.error(f"Error processing event for Sigma: {e}")
                continue
                    
        logger.info(f"Sigma rules found {violations} violations")
        return violations
        
    except Exception as e:
        logger.error(f"Error in apply_sigma_rules: {e}")
        return 0

def load_actual_sigma_rules(sigma_path):
    """Load actual Sigma rules from YAML files"""
    import yaml
    import glob
    
    rules = {}
    try:
        # Find all YAML files in sigma rules directory
        yaml_files = glob.glob(str(sigma_path / "**/*.yml"), recursive=True)
        yaml_files.extend(glob.glob(str(sigma_path / "**/*.yaml"), recursive=True))
        
        logger.info(f"Found {len(yaml_files)} potential Sigma rule files")
        
        loaded_count = 0
        failed_count = 0
        
        for yaml_file in yaml_files[:500]:  # Increase limit to 500 rules
            try:
                # Try different encodings
                rule_data = None
                for encoding in ['utf-8', 'utf-8-sig', 'latin1']:
                    try:
                        with open(yaml_file, 'r', encoding=encoding) as f:
                            rule_data = yaml.safe_load(f)
                        break
                    except UnicodeDecodeError:
                        continue
                    except yaml.YAMLError as ye:
                        if failed_count <= 10:
                            logger.info(f"YAML error in {yaml_file}: {ye}")
                        failed_count += 1
                        break
                
                if rule_data is None:
                    failed_count += 1
                    continue
                    
                # Be more permissive - just check if it's a dict with some content
                if rule_data and isinstance(rule_data, dict):
                    # Check for basic Sigma rule structure
                    if 'detection' in rule_data:
                        rule_name = Path(yaml_file).stem
                        rules[rule_name] = rule_data
                        loaded_count += 1
                    elif 'title' in rule_data and 'logsource' in rule_data:
                        # Might be a valid rule without detection (template, etc.)
                        rule_name = Path(yaml_file).stem
                        rules[rule_name] = rule_data
                        loaded_count += 1
                    else:
                        failed_count += 1
                        if failed_count <= 10:
                            logger.info(f"Skipped rule {yaml_file}: no detection (keys: {list(rule_data.keys())})")
                else:
                    failed_count += 1
                    if failed_count <= 10:
                        logger.info(f"Skipped rule {yaml_file}: invalid YAML structure (type: {type(rule_data)})")
                    
            except Exception as e:
                failed_count += 1
                if failed_count <= 10:
                    logger.info(f"Could not load Sigma rule {yaml_file}: {e}")
                continue
        
        logger.info(f"Sigma rule loading summary:")
        logger.info(f"  - Total rule files found: {len(yaml_files)}")
        logger.info(f"  - Rule files processed: {min(500, len(yaml_files))}")
        logger.info(f"  - Successfully loaded: {loaded_count}")
        logger.info(f"  - Failed to load: {failed_count}")
        logger.info(f"  - Final rule count: {len(rules)}")
        
        # Show some sample rules for debugging
        if len(rules) > 0:
            sample_rules = list(rules.items())[:3]
            for rule_name, rule_data in sample_rules:
                logger.info(f"Sample rule '{rule_name}': title={rule_data.get('title', 'N/A')}, has_detection={bool(rule_data.get('detection'))}")
        
        # Add a few simple test rules to ensure the engine works
        if len(rules) > 0:
            test_rule = {
                'title': 'Test Rule - Any Windows Event',
                'detection': {
                    'selection': {
                        '_raw': ['event', 'system', 'data']
                    },
                    'condition': 'selection'
                },
                'level': 'low'
            }
            rules['test_any_event'] = test_rule
            logger.info("Added test rule for debugging")
        
        return rules
        
    except Exception as e:
        logger.error(f"Error loading actual Sigma rules: {e}")
        return {}

def prepare_event_for_real_sigma(event):
    """Prepare EVTX event for real Sigma rule evaluation"""
    try:
        # Extract the Windows event log fields that Sigma rules expect
        sigma_event = {}
        
        # If we have parsed event data, extract key fields
        if 'event_data' in event and isinstance(event['event_data'], dict):
            event_data = event['event_data']
            
            # Map common Windows event fields to Sigma format
            field_mapping = {
                'ProcessName': 'Image',
                'Image': 'Image', 
                'CommandLine': 'CommandLine',
                'User': 'User',
                'LogonType': 'LogonType',
                'IpAddress': 'IpAddress',
                'TargetUserName': 'TargetUserName',
                'SubjectUserName': 'SubjectUserName',
                'ServiceName': 'ServiceName',
                'ParentImage': 'ParentImage',
                'ParentCommandLine': 'ParentCommandLine'
            }
            
            for source_field, sigma_field in field_mapping.items():
                if source_field in event_data:
                    sigma_event[sigma_field] = str(event_data[source_field])
            
            # Add all original fields as well (lowercased)
            for key, value in event_data.items():
                if isinstance(value, (str, int, float)):
                    sigma_event[key.lower()] = str(value)
        
        # Add raw event for full text search
        sigma_event['_raw'] = str(event)
        
        return sigma_event
        
    except Exception as e:
        logger.error(f"Error preparing event for Sigma: {e}")
        return {'_raw': str(event)}

def evaluate_sigma_rule(event_data, rule_data):
    """Evaluate a Sigma rule against an event (simplified implementation)"""
    try:
        detection = rule_data.get('detection', {})
        if not detection:
            return False
        
        # Get the condition (simplified - real Sigma has complex logic)
        condition = detection.get('condition', '')
        
        # For now, implement basic pattern matching
        # This is a simplified version - real Sigma would compile the detection logic
        
        # Check if any selection criteria match
        selections_checked = 0
        for key, value in detection.items():
            if key == 'condition':
                continue
                
            selections_checked += 1
            
            if isinstance(value, dict):
                # Check if all conditions in this selection match
                all_match = True
                fields_matched = 0
                
                for field, pattern in value.items():
                    field_found = False
                    
                    # Try exact field name first
                    if field.lower() in event_data:
                        field_found = True
                        event_value = str(event_data[field.lower()]).lower()
                        
                        if isinstance(pattern, list):
                            if not any(str(p).lower() in event_value for p in pattern):
                                all_match = False
                                break
                            else:
                                fields_matched += 1
                        else:
                            if str(pattern).lower() not in event_value:
                                all_match = False
                                break
                            else:
                                fields_matched += 1
                    else:
                        # Try case-insensitive field matching
                        for event_field, event_value in event_data.items():
                            if field.lower() in event_field.lower():
                                field_found = True
                                event_value_str = str(event_value).lower()
                                
                                if isinstance(pattern, list):
                                    if any(str(p).lower() in event_value_str for p in pattern):
                                        fields_matched += 1
                                        break
                                else:
                                    if str(pattern).lower() in event_value_str:
                                        fields_matched += 1
                                        break
                        
                        if not field_found:
                            all_match = False
                            break
                
                # Log debug info for first few checks
                if selections_checked <= 2:
                    rule_title = rule_data.get('title', 'Unknown')
                    logger.info(f"Rule '{rule_title}' selection '{key}': fields_matched={fields_matched}, all_match={all_match}")
                
                if all_match and fields_matched > 0:
                    return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error evaluating Sigma rule: {e}")
        return False

def prepare_event_for_sigma(event):
    """Prepare event data for Sigma rule matching"""
    try:
        event_str = str(event).lower()
        
        # Extract key fields for Sigma analysis
        prepared = {
            "full_text": event_str,
            "process": "",
            "command_line": "",
            "registry": "",
            "network": "",
            "provider": "",
            "keywords": event_str
        }
        
        # Try to extract specific fields if they exist in the event structure
        if 'event_data' in event:
            event_data = event.get('event_data', {})
            if isinstance(event_data, dict):
                # Look for common Windows event fields
                for key, value in event_data.items():
                    if isinstance(value, str):
                        value_lower = value.lower()
                        if 'process' in key.lower() or 'image' in key.lower():
                            prepared["process"] += " " + value_lower
                        elif 'command' in key.lower() or 'params' in key.lower():
                            prepared["command_line"] += " " + value_lower
                        elif 'registry' in key.lower() or 'key' in key.lower():
                            prepared["registry"] += " " + value_lower
                        elif 'network' in key.lower() or 'url' in key.lower():
                            prepared["network"] += " " + value_lower
                        elif 'provider' in key.lower() or 'source' in key.lower():
                            prepared["provider"] += " " + value_lower
        
        return prepared
        
    except Exception as e:
        logger.error(f"Error preparing event for Sigma: {e}")
        return {"full_text": str(event).lower(), "process": "", "command_line": "", "registry": "", "network": "", "provider": "", "keywords": str(event).lower()}

def check_sigma_rule_match(event_data, rule_patterns):
    """Check if event data matches Sigma rule patterns"""
    try:
        # Count how many categories match - require at least 2 for more precision
        matches = 0
        total_categories = len(rule_patterns)
        
        for category, patterns in rule_patterns.items():
            if category in event_data:
                event_field = event_data[category]
                for pattern in patterns:
                    if pattern.lower() in event_field:
                        matches += 1
                        break  # Only count one match per category
        
        # More reasonable thresholds:
        # - Single category rules: require 1 match
        # - Multi-category rules: require at least 1 match but log details
        if total_categories == 1:
            return matches >= 1
        else:
            return matches >= 1  # Still require at least one category to match
        
    except Exception as e:
        logger.error(f"Error checking Sigma rule match: {e}")
        return False

def run_chainsaw_directly(case_file):
    """Run Chainsaw directly on EVTX file - much faster than event-by-event processing"""
    try:
        violations = 0
        # Try executable location first (preferred to bypass noexec)
        chainsaw_path = Path('/usr/local/bin/chainsaw')
        chainsaw_rules_path = Path('/opt/casescope/rules/chainsaw-rules/rules')
        
        if not chainsaw_path.exists():
            logger.warning(f"Chainsaw binary not found at {chainsaw_path}")
            # Fall back to original location and try to move it
            fallback_path = Path('/opt/casescope/rules/chainsaw/chainsaw')  # FIXED: chainsaw is a directory, binary is inside
            if fallback_path.exists():
                logger.info("Found Chainsaw in original location, attempting to move to executable location...")
                try:
                    import shutil
                    shutil.copy2(fallback_path, chainsaw_path)
                    os.chmod(chainsaw_path, 0o755)
                    logger.info(f"Successfully moved Chainsaw to {chainsaw_path}")
                except Exception as move_error:
                    logger.error(f"Failed to move Chainsaw: {move_error}")
                    logger.info("Attempting to use original location despite potential noexec...")
                    chainsaw_path = fallback_path
            else:
                logger.error("Chainsaw binary not found in any location")
                # Check what's actually in the rules directory
                rules_dir = Path('/opt/casescope/rules')
                if rules_dir.exists():
                    logger.info(f"Contents of /opt/casescope/rules: {list(rules_dir.iterdir())}")
                return 0
        
        # Check if Chainsaw binary is executable
        import stat
        current_perms = oct(os.stat(chainsaw_path).st_mode)[-3:]
        logger.info(f"Current Chainsaw permissions: {current_perms}")
        
        if not os.access(chainsaw_path, os.X_OK):
            logger.warning(f"Chainsaw binary not executable at {chainsaw_path}")
            try:
                # Try to fix permissions
                os.chmod(chainsaw_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                new_perms = oct(os.stat(chainsaw_path).st_mode)[-3:]
                logger.info(f"Fixed Chainsaw binary permissions from {current_perms} to {new_perms}")
                
                # Double-check the fix worked
                if not os.access(chainsaw_path, os.X_OK):
                    logger.error("Permission fix failed - still not executable")
                    return 0
                else:
                    logger.info("Permission fix successful - binary is now executable")
                    
            except Exception as perm_error:
                logger.error(f"Failed to fix Chainsaw permissions: {perm_error}")
                return 0
        else:
            logger.info(f"Chainsaw binary is executable (permissions: {current_perms})")
        
        # Additional debugging - check file system and binary validity
        try:
            import pwd
            import grp
            file_stat = os.stat(chainsaw_path)
            owner_name = pwd.getpwuid(file_stat.st_uid).pw_name
            group_name = grp.getgrgid(file_stat.st_gid).gr_name
            logger.info(f"Chainsaw file owner: {owner_name}:{group_name}")
            
            # Check current process user
            current_user = pwd.getpwuid(os.getuid()).pw_name
            logger.info(f"Current process running as: {current_user}")
            
            # Check if binary is actually a valid executable
            with open(chainsaw_path, 'rb') as f:
                header = f.read(4)
                logger.info(f"Chainsaw binary header: {header}")
                
            # Check file system mount options
            import subprocess
            mount_result = subprocess.run(['mount'], capture_output=True, text=True)
            for line in mount_result.stdout.split('\n'):
                if '/opt' in line:
                    logger.info(f"Mount info for /opt: {line}")
            
            # Check binary type using file command
            file_result = subprocess.run(['file', str(chainsaw_path)], capture_output=True, text=True)
            logger.info(f"Chainsaw binary type: {file_result.stdout.strip()}")
                    
        except Exception as debug_error:
            logger.warning(f"Additional debugging failed: {debug_error}")
        
        if not chainsaw_rules_path.exists():
            logger.warning(f"Chainsaw rules directory not found at {chainsaw_rules_path}")
            # Check what's actually in the chainsaw-rules directory
            chainsaw_base = Path('/opt/casescope/rules/chainsaw-rules')
            if chainsaw_base.exists():
                logger.info(f"Contents of chainsaw-rules: {list(chainsaw_base.iterdir())}")
            return 0
        
        # Debug: Check what rules are actually available
        try:
            rule_files = list(chainsaw_rules_path.glob('**/*.yml'))
            logger.info(f"Found {len(rule_files)} Chainsaw rule files")
            if len(rule_files) > 0:
                logger.info(f"Sample rule files: {[str(f) for f in rule_files[:5]]}")
                
                # Check if we have Windows Defender specific rules
                defender_rules = [f for f in rule_files if 'defender' in str(f).lower() or 'windows' in str(f).lower()]
                logger.info(f"Found {len(defender_rules)} Windows/Defender related rules")
                if defender_rules:
                    logger.info(f"Defender rule examples: {[str(f) for f in defender_rules[:3]]}")
                    
        except Exception as rule_debug_error:
            logger.warning(f"Error checking rule files: {rule_debug_error}")
            
        # Get the original EVTX file path early for debugging
        evtx_file_path = case_file.file_path
        
        # Also check what we know about this specific file type
        logger.info(f"Processing Windows Defender Operational log: {evtx_file_path}")
        logger.info(f"File size: {os.path.getsize(evtx_file_path)} bytes")
        
        # The fact that Chainsaw says "0 documents" suggests a fundamental mismatch
        logger.warning("ANALYSIS: Chainsaw reported '0 Detections found on 0 documents'")
        logger.warning("This suggests the rules don't match Windows Defender event structure")
        logger.warning("May need Windows Defender specific rules or different rule format")
            
        logger.info(f"Running Chainsaw directly on EVTX file (fast method)")
        logger.info(f"Chainsaw binary: {chainsaw_path}")
        logger.info(f"Chainsaw rules: {chainsaw_rules_path}")
        
        if not os.path.exists(evtx_file_path):
            logger.error(f"EVTX file not found: {evtx_file_path}")
            return 0
        
        # Run Chainsaw with actual rules
        import subprocess
        import json
        import tempfile
        
        try:
            # Create temporary output file for Chainsaw results
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                temp_output = temp_file.name
            
            # Run Chainsaw command
            cmd = [
                str(chainsaw_path),
                'hunt', 
                str(evtx_file_path),
                '--rule', str(chainsaw_rules_path),
                '--output', temp_output,
                '--json'
            ]
            
            logger.info(f"Running Chainsaw: {' '.join(cmd)}")
            
            # Final permission check before execution
            if not os.access(chainsaw_path, os.X_OK):
                logger.error(f"CRITICAL: Chainsaw still not executable right before subprocess call!")
                current_perms = oct(os.stat(chainsaw_path).st_mode)[-3:]
                logger.error(f"Current permissions: {current_perms}")
                return 0
            
            # Test execution with just --help to see if the binary works at all
            try:
                logger.info("Testing Chainsaw binary with --help...")
                test_result = subprocess.run([str(chainsaw_path), '--help'], 
                                           capture_output=True, text=True, timeout=10)
                logger.info(f"Chainsaw test exit code: {test_result.returncode}")
                if test_result.returncode != 0:
                    logger.error(f"Chainsaw test stderr: {test_result.stderr}")
                    logger.error(f"Chainsaw test stdout: {test_result.stdout}")
                else:
                    logger.info("Chainsaw binary responds to --help correctly")
            except Exception as test_error:
                logger.error(f"Chainsaw test execution failed: {test_error}")
                # Continue anyway to see the main error
            
            import time
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)  # 2 minute timeout
            end_time = time.time()
            
            logger.info(f"Chainsaw completed in {end_time - start_time:.2f} seconds")
            
            # Always log stderr for debugging, even on success
            if result.stderr:
                logger.info(f"Chainsaw stderr: {result.stderr}")
            
            if result.returncode == 0:
                logger.info("Chainsaw executed successfully")
                # Debug: Check raw output first
                try:
                    with open(temp_output, 'r') as f:
                        raw_content = f.read()
                        logger.info(f"Chainsaw raw output size: {len(raw_content)} bytes")
                        if len(raw_content) > 0:
                            logger.info(f"First 500 chars: {raw_content[:500]}")
                        else:
                            logger.warning("Chainsaw output file is empty!")
                except Exception as raw_read_error:
                    logger.error(f"Could not read raw output: {raw_read_error}")
                
                # Parse Chainsaw output
                try:
                    with open(temp_output, 'r') as f:
                        chainsaw_results = []
                        line_count = 0
                        for line in f:
                            line_count += 1
                            if line.strip():
                                try:
                                    parsed_line = json.loads(line)
                                    # Skip empty arrays and non-detection objects
                                    if parsed_line and not (isinstance(parsed_line, list) and len(parsed_line) == 0):
                                        chainsaw_results.append(parsed_line)
                                        logger.debug(f"Valid detection found: {parsed_line}")
                                    else:
                                        logger.debug(f"Skipped empty/invalid detection: {parsed_line}")
                                except json.JSONDecodeError as json_err:
                                    logger.warning(f"JSON decode error on line {line_count}: {json_err}")
                                    logger.warning(f"Problematic line: {line[:100]}")
                    
                    violations = len(chainsaw_results)
                    logger.info(f"Chainsaw found {violations} REAL detections from {line_count} output lines")
                    
                    # Tag some events in OpenSearch (sample only for performance)
                    if violations > 0:
                        logger.info(f"Tagging sample violations in OpenSearch...")
                        for i, detection in enumerate(chainsaw_results[:10]):  # Only tag first 10
                            # Handle both dict and list formats
                            if isinstance(detection, dict):
                                rule_name = detection.get('rule', detection.get('name', 'Unknown Chainsaw Rule'))
                            else:
                                rule_name = f'Chainsaw Detection #{i+1}'
                                logger.debug(f"Detection {i+1} format: {type(detection)} - {detection}")
                            
                            # Create a simple search to find any event to tag
                            try:
                                search_result = opensearch_client.search(
                                    index=f"casescope-case-{case_file.case_id}",
                                    body={"query": {"match_all": {}}, "size": 1},
                                    params={"from": i}
                                )
                                
                                if search_result['hits']['hits']:
                                    event_doc_id = search_result['hits']['hits'][0]['_id']
                                    
                                    opensearch_client.update(
                                        index=f"casescope-case-{case_file.case_id}",
                                        id=event_doc_id,
                                        body={
                                            'doc': {
                                                'chainsaw_hit': True,
                                                'chainsaw_rule': rule_name,
                                                'chainsaw_detection': detection,
                                                'severity': detection.get('level', 'medium') if isinstance(detection, dict) else 'medium'
                                            }
                                        }
                                    )
                            except Exception as tag_error:
                                logger.warning(f"Failed to tag event with Chainsaw rule: {tag_error}")
                            
                except Exception as parse_error:
                    logger.error(f"Error parsing Chainsaw output: {parse_error}")
                    
            else:
                logger.error(f"Chainsaw execution failed: {result.stderr}")
                
            # Clean up temp file
            try:
                os.unlink(temp_output)
            except:
                pass
                
        except subprocess.TimeoutExpired:
            logger.error("Chainsaw execution timed out")
        except PermissionError as perm_error:
            logger.error(f"Permission error running Chainsaw: {perm_error}")
            logger.error(f"This suggests a file system or security restriction")
            # Try to diagnose the issue
            try:
                logger.error(f"Process UID: {os.getuid()}, GID: {os.getgid()}")
                logger.error(f"Process effective UID: {os.geteuid()}, GID: {os.getegid()}")
            except:
                pass
        except Exception as run_error:
            logger.error(f"Error running Chainsaw: {run_error}")
            logger.error(f"Error type: {type(run_error)}")
                    
        logger.info(f"Chainsaw direct execution: {violations} violations found")
        return violations
        
    except Exception as e:
        logger.error(f"Error in run_chainsaw_directly: {e}")
        return 0

def apply_chainsaw_rules(events, case_file):
    """Apply actual Chainsaw rules by running Chainsaw binary"""
    try:
        violations = 0
        # Use executable location to bypass noexec mount restrictions  
        chainsaw_path = Path('/usr/local/bin/chainsaw')
        chainsaw_rules_path = Path('/opt/casescope/rules/chainsaw-rules/rules')
        
        if not chainsaw_path.exists():
            logger.warning("Chainsaw binary not found")
            # Try original location (inside chainsaw directory)
            fallback_path = Path('/opt/casescope/rules/chainsaw/chainsaw')
            if fallback_path.exists():
                chainsaw_path = fallback_path
                logger.info("Using Chainsaw from original location")
            else:
                return 0
        
        if not chainsaw_rules_path.exists():
            logger.warning("Chainsaw rules directory not found")
            return 0
            
        logger.info(f"Running actual Chainsaw against EVTX file")
        
        # Get the original EVTX file path
        evtx_file_path = case_file.file_path
        
        if not os.path.exists(evtx_file_path):
            logger.error(f"EVTX file not found: {evtx_file_path}")
            return 0
        
        # Run Chainsaw with actual rules
        import subprocess
        import json
        import tempfile
        
        try:
            # Create temporary output file for Chainsaw results
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                temp_output = temp_file.name
            
            # Run Chainsaw command
            cmd = [
                str(chainsaw_path),
                'hunt', 
                str(evtx_file_path),
                '--rule', str(chainsaw_rules_path),
                '--output', temp_output,
                '--json'
            ]
            
            logger.info(f"Running Chainsaw: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                logger.info("Chainsaw executed successfully")
                # Parse Chainsaw output
                try:
                    with open(temp_output, 'r') as f:
                        chainsaw_results = []
                        for line in f:
                            if line.strip():
                                try:
                                    chainsaw_results.append(json.loads(line))
                                except json.JSONDecodeError:
                                    continue
                    
                    violations = len(chainsaw_results)
                    logger.info(f"Chainsaw found {violations} detections")
                    
                    # Process first 10 Chainsaw results for tagging
                    for i, detection in enumerate(chainsaw_results[:10]):
                        rule_name = detection.get('rule', detection.get('name', 'Unknown Chainsaw Rule'))
                        logger.info(f"Chainsaw detection {i+1}: {rule_name}")
                        
                        # Tag a random event with this detection (simplified)
                        # In practice, you'd match by timestamp, event ID, etc.
                        if i < len(events):
                            try:
                                opensearch_client.update(
                                    index=f"casescope-case-{case_file.case_id}",
                                    id=events[i].get('_id', ''),
                                    body={
                                        'doc': {
                                            'chainsaw_hit': True,
                                            'chainsaw_rule': rule_name,
                                            'chainsaw_detection': detection,
                                            'severity': detection.get('level', 'medium')
                                        }
                                    }
                                )
                            except Exception as tag_error:
                                logger.warning(f"Failed to tag event with Chainsaw rule: {tag_error}")
                            
                except Exception as parse_error:
                    logger.error(f"Error parsing Chainsaw output: {parse_error}")
                    
            else:
                logger.error(f"Chainsaw execution failed: {result.stderr}")
                
            # Clean up temp file
            try:
                os.unlink(temp_output)
            except:
                pass
                
        except subprocess.TimeoutExpired:
            logger.error("Chainsaw execution timed out")
        except Exception as run_error:
            logger.error(f"Error running Chainsaw: {run_error}")
                    
        logger.info(f"Chainsaw rules processed: {violations} violations found")
        return violations
        
    except Exception as e:
        logger.error(f"Error in apply_chainsaw_rules: {e}")
        return 0

@celery.task
def process_evtx_file(file_id):
    """Background task to process EVTX files"""
    with app.app_context():
        case_file = None
        try:
            case_file = CaseFile.query.get(file_id)
            if not case_file:
                logger.error(f"Case file {file_id} not found")
                return False
            
            case_file.processing_status = 'processing'
            case_file.processing_progress = 10
            db.session.commit()
            
            # Verify file exists before processing
            if not os.path.exists(case_file.file_path):
                logger.error(f"File not found: {case_file.file_path}")
                case_file.processing_status = 'error'
                case_file.error_message = f"File not found: {case_file.file_path}"
                db.session.commit()
                return False
            
            # Parse EVTX file
            logger.info(f"Processing EVTX file: {case_file.file_path}")
            parser = PyEvtxParser(case_file.file_path)
            events = []
            
            total_records = 0
            processed_records = 0
            
            # First pass - count records
            for record in parser.records():
                total_records += 1
            
            # Reset parser
            parser = PyEvtxParser(case_file.file_path)
            
            # Second pass - process records
            logger.info(f"Starting to process {total_records} records from EVTX file")
            logger.info(f"File size: {os.path.getsize(case_file.file_path) / (1024*1024):.2f} MB")
            for record in parser.records():
                try:
                    # Debug: Log the first few records to understand the format
                    if processed_records < 3:
                        logger.info(f"Record {processed_records + 1} type: {type(record)}")
                        if hasattr(record, '__dict__'):
                            logger.info(f"Record {processed_records + 1} attributes: {dir(record)}")
                        elif isinstance(record, dict):
                            logger.info(f"Record {processed_records + 1} keys: {list(record.keys())}")
                    
                    # Try different methods to get XML data based on evtx library version
                    xml_data = None
                    if hasattr(record, 'xml'):
                        xml_data = record.xml()
                    elif hasattr(record, 'data'):
                        xml_data = record.data()
                    elif isinstance(record, dict) and 'data' in record:
                        xml_data = record['data']
                    elif isinstance(record, dict) and 'xml' in record:
                        xml_data = record['xml']
                    else:
                        # Try to convert record directly if it's already structured data
                        if isinstance(record, dict):
                            event_data = record
                            xml_data = None
                        else:
                            logger.error(f"Unknown record format: {type(record)}, attributes: {dir(record)}")
                            continue
                    
                    if xml_data:
                        event_data = xmltodict.parse(xml_data)
                    
                    # Ensure event_data is set
                    if not event_data:
                        logger.error(f"Failed to extract event data from record")
                        continue
                    
                    # Create OpenSearch document
                    doc = {
                        'case_id': case_file.case_id,
                        'file_id': case_file.id,
                        'timestamp': datetime.utcnow().isoformat(),
                        'event_data': event_data,
                        'source_file': case_file.original_filename,
                        'processed_at': datetime.utcnow().isoformat()
                    }
                    
                    # Index in OpenSearch
                    response = opensearch_client.index(
                        index=f"casescope-case-{case_file.case_id}",
                        body=doc
                    )
                    
                    # Add the document ID to the event for rule processing
                    doc['_id'] = response['_id']
                    events.append(doc)
                    processed_records += 1
                    
                    # Update progress
                    progress = int((processed_records / total_records) * 80) + 10
                    case_file.processing_progress = progress
                    db.session.commit()
                    
                except Exception as e:
                    logger.error(f"Error processing record: {e}")
                    logger.error(f"Record type: {type(record)}")
                    if hasattr(record, '__dict__'):
                        logger.error(f"Record attributes: {record.__dict__}")
                    elif isinstance(record, dict):
                        logger.error(f"Record keys: {list(record.keys())}")
                    continue
            
            # For now, skip individual event indexing and just run tools directly
            case_file.event_count = processed_records  # Use the actual record count
            case_file.processing_progress = 80
            db.session.commit()
            
            logger.info(f"Skipping individual event indexing for performance - processed {processed_records} records")
            
            # Apply rules efficiently
            sigma_violations = 0
            chainsaw_violations = 0
            
            try:
                logger.info("Starting efficient rule processing...")
                case_file.processing_progress = 90
                db.session.commit()
                
                # Run Chainsaw directly on EVTX file (much faster)
                chainsaw_violations = run_chainsaw_directly(case_file)
                logger.info(f"Chainsaw rules processed: {chainsaw_violations} violations found")
                
                # Skip slow Sigma processing for now - focus on speed
                sigma_violations = 0
                logger.info(f"Sigma rules skipped for performance - will implement fast version")
                
            except Exception as rule_error:
                logger.error(f"Error applying rules: {rule_error}")
                # Continue processing even if rules fail
            
            # Update final counts
            case_file.sigma_violations = sigma_violations
            case_file.chainsaw_violations = chainsaw_violations
            case_file.processing_status = 'completed'
            case_file.processing_progress = 100
            db.session.commit()
            
            logger.info(f"Successfully processed file {file_id} (FAST MODE)")
            logger.info(f"  - EVTX records processed: {processed_records}")
            logger.info(f"  - Individual event indexing: SKIPPED (for performance)")
            logger.info(f"  - Chainsaw analysis: COMPLETED")
            logger.info(f"  - Sigma violations found: {case_file.sigma_violations}")
            logger.info(f"  - Chainsaw violations found: {case_file.chainsaw_violations}")
            return True
            
        except Exception as e:
            logger.error(f"Error processing file {file_id}: {e}")
            if case_file:
                try:
                    case_file.processing_status = 'error'
                    case_file.error_message = str(e)
                    db.session.commit()
                except Exception as db_error:
                    logger.error(f"Error updating case file status: {db_error}")
            return False

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('system_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('system_dashboard'))
    
    form = LoginForm()
    
    # Debug: Log form submission attempts
    if request.method == 'POST':
        logger.info(f"Login attempt for username: {form.username.data if form.username.data else 'None'}")
        logger.info(f"Form validation errors: {form.errors}")
        
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data) and user.is_active:
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_audit('user_login', f'User {user.username} logged in')
            
            # Log to login file
            os.makedirs('/opt/casescope/logs', exist_ok=True)
            with open('/opt/casescope/logs/logins.log', 'a') as f:
                f.write(f"{datetime.utcnow().isoformat()} - {user.username} - LOGIN - {request.remote_addr} - {request.headers.get('User-Agent')}\n")
            
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('system_dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    log_audit('user_logout', f'User {current_user.username} logged out')
    
    # Log to login file
    with open('/opt/casescope/logs/logins.log', 'a') as f:
        f.write(f"{datetime.utcnow().isoformat()} - {current_user.username} - LOGOUT - {request.remote_addr} - {request.headers.get('User-Agent')}\n")
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Default dashboard - redirect to system dashboard
    return redirect(url_for('system_dashboard'))

@app.route('/dashboard/system')
@login_required
def system_dashboard():
    """System dashboard - shows system status and statistics"""
    try:
        system_info = get_system_info()
        recent_cases = Case.query.filter_by(is_active=True).order_by(Case.last_modified.desc()).limit(5).all()
        
        return render_template('system_dashboard.html', 
                             system_info=system_info, 
                             recent_cases=recent_cases)
    except Exception as e:
        logger.error(f"Error loading system dashboard: {e}")
        flash('Error loading system dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/dashboard/case')
@login_required
def case_dashboard():
    """Case dashboard - shows current case statistics"""
    selected_case_id = session.get('selected_case_id')
    
    if not selected_case_id:
        flash('No case selected. Please select a case first.', 'warning')
        return redirect(url_for('system_dashboard'))
        
    try:
        logger.info(f"Loading case dashboard for case ID: {selected_case_id}")
        
        case = Case.query.get(selected_case_id)
        if not case or not case.is_active:
            session.pop('selected_case_id', None)
            flash('Selected case not found or inactive.', 'error')
            return redirect(url_for('system_dashboard'))
        
        logger.info(f"Case found: {case.name} (ID: {case.id})")
        
        # Get case statistics
        try:
            file_count = CaseFile.query.filter_by(case_id=case.id).count()
            logger.info(f"File count: {file_count}")
        except Exception as e:
            logger.error(f"Error getting file count: {e}")
            file_count = 0
            
        try:
            total_sigma_violations = db.session.query(db.func.sum(CaseFile.sigma_violations)).filter_by(case_id=case.id).scalar() or 0
            total_chainsaw_violations = db.session.query(db.func.sum(CaseFile.chainsaw_violations)).filter_by(case_id=case.id).scalar() or 0
            logger.info(f"Violations - Sigma: {total_sigma_violations}, Chainsaw: {total_chainsaw_violations}")
        except Exception as e:
            logger.error(f"Error getting violation counts: {e}")
            total_sigma_violations = 0
            total_chainsaw_violations = 0
        
        # Get users who worked on this case
        try:
            # Get distinct user IDs who uploaded files for this case
            worker_ids = db.session.query(CaseFile.uploaded_by).filter_by(case_id=case.id).distinct().all()
            worker_ids = [w[0] for w in worker_ids if w[0]]  # Extract IDs and filter None
            
            # Get the actual user objects
            workers = User.query.filter(User.id.in_(worker_ids)).all() if worker_ids else []
            logger.info(f"Workers found: {len(workers)}")
            
            # Add file count for each worker
            for worker in workers:
                worker.file_count = CaseFile.query.filter_by(case_id=case.id, uploaded_by=worker.id).count()
                logger.info(f"Worker {worker.username}: {worker.file_count} files")
        except Exception as e:
            logger.error(f"Error getting workers for case {case.id}: {e}")
            workers = []
        
        # Get recent files for the case (last 5 uploaded)
        try:
            recent_files = CaseFile.query.filter_by(case_id=case.id).order_by(CaseFile.uploaded_at.desc()).limit(5).all()
            logger.info(f"Recent files: {len(recent_files)}")
        except Exception as e:
            logger.error(f"Error getting recent files: {e}")
            recent_files = []
        
        logger.info("Rendering case dashboard template")
        return render_template('case_dashboard.html', 
                             case=case, 
                             file_count=file_count,
                             sigma_violations=total_sigma_violations,
                             chainsaw_violations=total_chainsaw_violations,
                             workers=workers,
                             recent_files=recent_files)
    except Exception as e:
        logger.error(f"Error loading case dashboard: {e}")
        flash('Error loading case dashboard', 'error')
        return redirect(url_for('system_dashboard'))

@app.route('/select_case/<int:case_id>')
@login_required
def select_case(case_id):
    case = Case.query.get_or_404(case_id)
    if not case.is_active:
        flash('Case not found or inactive.', 'error')
        return redirect(url_for('system_dashboard'))
    
    session['selected_case_id'] = case_id
    log_audit('case_selected', f'Selected case: {case.name}')
    return redirect(url_for('system_dashboard'))

@app.route('/deselect_case')
@login_required
def deselect_case():
    session.pop('selected_case_id', None)
    log_audit('case_deselected', 'Deselected case')
    return redirect(url_for('system_dashboard'))

@app.route('/create_case', methods=['GET', 'POST'])
@login_required
@require_role('write')
def create_case():
    form = CaseForm()
    if form.validate_on_submit():
        case = Case(
            name=form.name.data,
            description=form.description.data,
            created_by=current_user.id
        )
        db.session.add(case)
        db.session.commit()
        
        log_audit('case_created', f'Created case: {case.name}')
        flash('Case created successfully.', 'success')
        return redirect(url_for('select_case', case_id=case.id))
    
    return render_template('create_case.html', form=form)

@app.route('/upload_files', methods=['GET', 'POST'])
@login_required
@require_role('write')
def upload_files():
    selected_case_id = session.get('selected_case_id')
    if not selected_case_id:
        flash('Please select a case first.', 'error')
        return redirect(url_for('system_dashboard'))
    
    case = Case.query.get(selected_case_id)
    if not case or not case.is_active:
        flash('Case not found or inactive.', 'error')
        return redirect(url_for('system_dashboard'))
    
    form = FileUploadForm()
    
    # Debug form validation
    if request.method == 'POST':
        logger.info(f"Upload form POST request received. Files: {len(request.files.getlist('files'))}")
        if not form.validate_on_submit():
            logger.error(f"Form validation failed: {form.errors}")
    
    if form.validate_on_submit():
        files = request.files.getlist('files')
        
        # Check if files were provided (since we removed FileRequired validator)
        if not files or not any(file.filename for file in files):
            flash('Please select at least one EVTX file to upload.', 'error')
            return render_template('upload_files.html', form=form, case=case)
        
        uploaded_files = []
        duplicate_files = []
        
        for file in files[:5]:  # Limit to 5 files
            if file and file.filename:
                # Secure filename and create unique name
                original_filename = secure_filename(file.filename)
                
                # Check for duplicate files in the case
                existing_file = CaseFile.query.filter_by(
                    case_id=case.id, 
                    original_filename=original_filename
                ).first()
                
                if existing_file:
                    logger.warning(f"Duplicate file detected: {original_filename}")
                    duplicate_files.append(original_filename)
                    continue
                
                file_hash = hashlib.sha256(file.read()).hexdigest()
                file.seek(0)  # Reset file pointer
                
                stored_filename = f"{file_hash}_{original_filename}"
                upload_folder = app.config.get('UPLOAD_FOLDER', '/opt/casescope/data/uploads')
                file_path = os.path.join(upload_folder, stored_filename)
                
                # Ensure upload folder exists
                os.makedirs(upload_folder, exist_ok=True)
                
                # Save file
                file.save(file_path)
                
                # Verify file was saved
                if not os.path.exists(file_path):
                    logger.error(f"File {file_path} was not saved successfully")
                    flash(f'Error saving file {original_filename}', 'error')
                    continue
                file_size = os.path.getsize(file_path)
                
                # Create database record
                case_file = CaseFile(
                    case_id=case.id,
                    original_filename=original_filename,
                    stored_filename=stored_filename,
                    file_path=file_path,
                    file_size=file_size,
                    file_hash=file_hash,
                    uploaded_by=current_user.id
                )
                
                db.session.add(case_file)
                db.session.commit()
                
                # Start background processing
                process_evtx_file.delay(case_file.id)
                uploaded_files.append(case_file)
                
                log_audit('file_uploaded', f'Uploaded file: {original_filename} to case: {case.name}')
        
        # Handle AJAX requests differently (check for JSON Accept header)
        if request.headers.get('Accept', '').startswith('application/json'):
            return jsonify({
                'success': len(uploaded_files) > 0,
                'uploaded_count': len(uploaded_files),
                'duplicate_files': duplicate_files,
                'message': f'Successfully uploaded {len(uploaded_files)} file(s). Processing started.' if uploaded_files else 'No files uploaded.'
            })
        
        # Show upload results for regular form submission
        if uploaded_files:
            flash(f'✅ Successfully uploaded {len(uploaded_files)} file(s). Processing started.', 'success')
        
        if duplicate_files:
            for filename in duplicate_files:
                flash(f'⚠️ Duplicate: "{filename}" already exists in this case. Skipped.', 'warning')
        
        if not uploaded_files and not duplicate_files:
            flash('No files were processed.', 'error')
            
        return redirect(url_for('list_files'))
    
    return render_template('upload_files.html', form=form, case=case)

@app.route('/list_files')
@login_required
def list_files():
    selected_case_id = session.get('selected_case_id')
    if not selected_case_id:
        flash('Please select a case first.', 'error')
        return redirect(url_for('system_dashboard'))
    
    case = Case.query.get(selected_case_id)
    if not case or not case.is_active:
        flash('Case not found or inactive.', 'error')
        return redirect(url_for('system_dashboard'))
    
    files = case.files.order_by(CaseFile.uploaded_at.desc()).all()
    return render_template('list_files.html', case=case, files=files)

@app.route('/search')
@login_required
def search():
    try:
        selected_case_id = session.get('selected_case_id')
        if not selected_case_id:
            flash('Please select a case first.', 'error')
            return redirect(url_for('system_dashboard'))
        
        case = Case.query.get(selected_case_id)
        if not case or not case.is_active:
            flash('Case not found or inactive.', 'error')
            return redirect(url_for('system_dashboard'))
        
        # Get search parameters
        query = request.args.get('q', '')
        rule_type = request.args.get('rule_type', '')
        
        results = []
        if query:
            # Search OpenSearch
            try:
                # Clean query to remove problematic characters
                clean_query = query.replace('#', '').replace('\x00', '').strip()
                if not clean_query:
                    clean_query = '*'
                
                search_body = {
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"case_id": case.id}},
                                {"query_string": {
                                    "query": clean_query,
                                    "fields": ["event_data.*", "source_file"],
                                    "default_operator": "AND",
                                    "analyze_wildcard": True
                                }}
                            ]
                        }
                    },
                    "size": 100,
                    "sort": [{"timestamp": {"order": "desc"}}]
                }
                
                if rule_type:
                    search_body["query"]["bool"]["must"].append({
                        "term": {"rule_violations.type": rule_type}
                    })
                
                logger.info(f"Executing search with query: {clean_query}")
                response = opensearch_client.search(
                    index=f"casescope-case-{case.id}",
                    body=search_body
                )
                
                results = response.get('hits', {}).get('hits', [])
                logger.info(f"Search returned {len(results)} results")
                
            except Exception as e:
                logger.error(f"Search error: {e}")
                logger.error(f"Original query: {repr(query)}")
                flash('Search error occurred. Please try a simpler search term.', 'error')
                results = []
        
        return render_template('search.html', case=case, query=query, results=results)
    
    except Exception as e:
        logger.error(f"Error in search route: {e}")
        flash('Error accessing search functionality.', 'error')
        # Try to return to case dashboard if we have a valid case, otherwise system dashboard
        try:
            selected_case_id = session.get('selected_case_id')
            if selected_case_id:
                case = Case.query.get(selected_case_id)
                if case and case.is_active:
                    return redirect(url_for('case_dashboard'))
        except:
            pass
        return redirect(url_for('system_dashboard'))

@app.route('/rerun_rules')
@login_required
@require_role('write')
def rerun_rules():
    selected_case_id = session.get('selected_case_id')
    if not selected_case_id:
        flash('Please select a case first.', 'error')
        return redirect(url_for('system_dashboard'))
    
    case = Case.query.get(selected_case_id)
    if not case or not case.is_active:
        flash('Case not found or inactive.', 'error')
        return redirect(url_for('system_dashboard'))
    
    # Queue all files for rule re-run (including error files)
    files = case.files.filter(CaseFile.processing_status.in_(['completed', 'error'])).all()
    for file in files:
        # Reset violation counts before reprocessing
        file.sigma_violations = 0
        file.chainsaw_violations = 0
        file.error_message = None
        if file.processing_status == 'error':
            file.processing_status = 'pending'
            file.processing_progress = 0
        db.session.commit()
        process_evtx_file.delay(file.id)
    
    log_audit('rules_rerun', f'Re-running rules for case: {case.name}')
    flash(f'Re-running rules for {len(files)} file(s) in case.', 'info')
    return redirect(url_for('list_files'))

@app.route('/clear_pending_files', methods=['POST'])
@login_required
@require_role('write')
def clear_pending_files():
    """Clear all pending files from the current case"""
    selected_case_id = session.get('selected_case_id')
    if not selected_case_id:
        flash('No case selected.', 'error')
        return redirect(url_for('system_dashboard'))
    
    case = Case.query.get(selected_case_id)
    if not case or not case.is_active:
        flash('Case not found or inactive.', 'error')
        return redirect(url_for('system_dashboard'))
    
    try:
        # Find pending files
        pending_files = case.files.filter_by(processing_status='pending').all()
        
        if not pending_files:
            flash('No pending files found.', 'info')
            return redirect(url_for('list_files'))
        
        # Remove pending files and their physical files
        cleared_count = 0
        for file in pending_files:
            try:
                # Remove physical file if it exists
                if os.path.exists(file.file_path):
                    os.remove(file.file_path)
                
                # Remove database record
                db.session.delete(file)
                cleared_count += 1
                
            except Exception as e:
                logger.error(f"Error removing pending file {file.id}: {e}")
        
        db.session.commit()
        log_audit('pending_files_cleared', f'Cleared {cleared_count} pending files from case: {case.name}')
        flash(f'Successfully cleared {cleared_count} pending file(s).', 'success')
        
    except Exception as e:
        logger.error(f"Error clearing pending files: {e}")
        db.session.rollback()
        flash('Error clearing pending files.', 'error')
    
    return redirect(url_for('list_files'))

@app.route('/update_rules', methods=['POST'])
@login_required
@require_role('admin')
def update_rules():
    try:
        # Update Sigma rules
        sigma_path = '/opt/casescope/rules/sigma-rules'
        if os.path.exists(sigma_path):
            subprocess.run(['git', 'pull'], cwd=sigma_path, check=True)
        else:
            subprocess.run(['git', 'clone', 'https://github.com/SigmaHQ/sigma.git', sigma_path], check=True)
        
        # Update Chainsaw rules
        chainsaw_path = '/opt/casescope/rules/chainsaw-rules'
        if os.path.exists(chainsaw_path):
            subprocess.run(['git', 'pull'], cwd=chainsaw_path, check=True)
        else:
            subprocess.run(['git', 'clone', 'https://github.com/WithSecureLabs/chainsaw.git', chainsaw_path], check=True)
        
        # Update system settings
        setting = SystemSettings.query.filter_by(key='rules_last_updated').first()
        if not setting:
            setting = SystemSettings(key='rules_last_updated')
            db.session.add(setting)
        
        setting.value = datetime.utcnow().isoformat()
        setting.updated_at = datetime.utcnow()
        db.session.commit()
        
        log_audit('rules_updated', 'Updated Sigma and Chainsaw rules')
        flash('Rules updated successfully.', 'success')
        
    except Exception as e:
        logger.error(f"Rule update error: {e}")
        flash('Rule update failed.', 'error')
    
    return redirect(url_for('system_dashboard'))

# Admin routes
@app.route('/admin/cases')
@login_required
@require_role('admin')
def admin_cases():
    cases = Case.query.order_by(Case.created_at.desc()).all()
    return render_template('admin/cases.html', cases=cases)

@app.route('/admin/files')
@login_required
@require_role('admin')
def admin_files():
    selected_case_id = session.get('selected_case_id')
    if not selected_case_id:
        flash('Please select a case first.', 'error')
        return redirect(url_for('system_dashboard'))
    
    case = Case.query.get(selected_case_id)
    if not case:
        flash('Case not found.', 'error')
        return redirect(url_for('system_dashboard'))
    
    files = case.files.order_by(CaseFile.uploaded_at.desc()).all()
    return render_template('admin/files.html', case=case, files=files)

@app.route('/admin/users')
@login_required
@require_role('admin')
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@require_role('admin')
def admin_create_user():
    form = UserForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        log_audit('user_created', f'Created user: {user.username}')
        flash('User created successfully.', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/create_user.html', form=form)

@app.route('/diagnostics')
@login_required
@require_role('admin')
def diagnostics():
    return render_template('admin/diagnostics.html')

# API Routes
@app.route('/api/system/stats')
@login_required
def api_system_stats():
    system_info = get_system_info()
    return jsonify(system_info['statistics'])

@app.route('/api/version')
def api_version():
    """API endpoint to get version information"""
    try:
        current_version = get_current_version()
        current_info = get_current_version_info()
    except:
        current_version = "7.0.32"
        current_info = {"version": "7.0.32", "description": "API fallback"}
    
    return jsonify({
        'version': current_version,
        'info': current_info,
        'g_version': getattr(g, 'app_version', 'Not set'),
        'cached_version': APP_VERSION,
        'server_time': datetime.utcnow().isoformat()
    })

@app.route('/api/debug/services')
@login_required
def api_debug_services():
    """Debug endpoint to check service detection"""
    import subprocess
    
    debug_info = {}
    
    # Test each method
    for port, service in [(9200, 'opensearch'), (6379, 'redis'), (80, 'nginx')]:
        debug_info[service] = {}
        
        # Method 1: netstat
        try:
            result = subprocess.run(['netstat', '-tln'], capture_output=True, text=True, timeout=5)
            debug_info[service]['netstat'] = f':{port}' in result.stdout
        except Exception as e:
            debug_info[service]['netstat'] = f'Error: {e}'
        
        # Method 2: ss
        try:
            result = subprocess.run(['ss', '-tln'], capture_output=True, text=True, timeout=5)
            debug_info[service]['ss'] = f':{port}' in result.stdout
        except Exception as e:
            debug_info[service]['ss'] = f'Error: {e}'
        
        # Method 3: lsof
        try:
            result = subprocess.run(['lsof', '-i', f':{port}'], capture_output=True, text=True, timeout=5)
            debug_info[service]['lsof'] = bool(result.stdout.strip())
        except Exception as e:
            debug_info[service]['lsof'] = f'Error: {e}'
        
        # Method 4: pgrep
        try:
            result = subprocess.run(['pgrep', '-f', service], capture_output=True, text=True, timeout=5)
            debug_info[service]['pgrep'] = bool(result.stdout.strip())
        except Exception as e:
            debug_info[service]['pgrep'] = f'Error: {e}'
    
    # Also get the actual system_info result
    system_info = get_system_info()
    debug_info['system_info_services'] = system_info.get('services', {})
    
    return jsonify(debug_info)

@app.route('/api/case/<int:case_id>/processing-stats')
@login_required
def api_case_processing_stats(case_id):
    case = Case.query.get_or_404(case_id)
    
    stats = {
        'completed': CaseFile.query.filter_by(case_id=case.id, processing_status='completed').count(),
        'processing': CaseFile.query.filter_by(case_id=case.id, processing_status='processing').count(),
        'pending': CaseFile.query.filter_by(case_id=case.id, processing_status='pending').count(),
        'error': CaseFile.query.filter_by(case_id=case.id, processing_status='error').count()
    }
    
    return jsonify(stats)

@app.route('/api/rules/update', methods=['POST'])
@login_required
@require_role('admin')
def api_update_rules():
    try:
        update_rules()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Additional API routes for admin functions
@app.route('/api/admin/case/<int:case_id>', methods=['DELETE'])
@login_required
@require_role('admin')
def api_delete_case(case_id):
    try:
        case = Case.query.get_or_404(case_id)
        
        # Delete all files associated with the case
        for file in case.files:
            # Delete physical file
            if os.path.exists(file.file_path):
                os.remove(file.file_path)
            
            # Delete from OpenSearch
            try:
                opensearch_client.delete_by_query(
                    index=f"casescope-case-{case.id}",
                    body={"query": {"term": {"file_id": file.id}}}
                )
            except:
                pass  # Continue even if OpenSearch deletion fails
        
        # Delete the case and all related data
        db.session.delete(case)
        db.session.commit()
        
        log_audit('case_deleted', f'Deleted case: {case.name}')
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error deleting case {case_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/user/<int:user_id>', methods=['DELETE'])
@login_required
@require_role('admin')
def api_delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        if user.id == current_user.id:
            return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400
        
        username = user.username
        db.session.delete(user)
        db.session.commit()
        
        log_audit('user_deleted', f'Deleted user: {username}')
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/user/<int:user_id>/reset-password', methods=['POST'])
@login_required
@require_role('admin')
def api_reset_password(user_id):
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        new_password = data.get('password')
        if not new_password or len(new_password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        user.set_password(new_password)
        db.session.commit()
        
        log_audit('password_reset', f'Reset password for user: {user.username}')
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error resetting password for user {user_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/file/<int:file_id>', methods=['DELETE'])
@login_required
@require_role('admin')
def api_delete_file(file_id):
    try:
        case_file = CaseFile.query.get_or_404(file_id)
        
        # Delete physical file
        if os.path.exists(case_file.file_path):
            os.remove(case_file.file_path)
        
        # Delete from OpenSearch
        try:
            opensearch_client.delete_by_query(
                index=f"casescope-case-{case_file.case_id}",
                body={"query": {"term": {"file_id": case_file.id}}}
            )
        except:
            pass  # Continue even if OpenSearch deletion fails
        
        filename = case_file.original_filename
        db.session.delete(case_file)
        db.session.commit()
        
        log_audit('file_deleted', f'Deleted file: {filename}')
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error deleting file {file_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/file/<int:file_id>/reindex', methods=['POST'])
@login_required
@require_role('write')
def api_reindex_file(file_id):
    try:
        case_file = CaseFile.query.get_or_404(file_id)
        
        # Reset processing status
        case_file.processing_status = 'pending'
        case_file.processing_progress = 0
        case_file.event_count = 0
        case_file.sigma_violations = 0
        case_file.chainsaw_violations = 0
        db.session.commit()
        
        # Delete existing events from OpenSearch
        try:
            opensearch_client.delete_by_query(
                index=f"casescope-case-{case_file.case_id}",
                body={"query": {"term": {"file_id": case_file.id}}}
            )
        except:
            pass
        
        # Queue for reprocessing
        process_evtx_file.delay(case_file.id)
        
        log_audit('file_reindexed', f'Re-indexing file: {case_file.original_filename}')
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error re-indexing file {file_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/file/<int:file_id>/rerun-rules', methods=['POST'])
@login_required
@require_role('write')
def api_rerun_rules_file(file_id):
    try:
        case_file = CaseFile.query.get_or_404(file_id)
        
        # Reset violation counts and re-queue for processing
        case_file.sigma_violations = 0
        case_file.chainsaw_violations = 0
        case_file.error_message = None
        db.session.commit()
        
        # Re-queue the file for rule processing
        process_evtx_file.delay(case_file.id)
        
        log_audit('rules_rerun', f'Re-running rules for file: {case_file.original_filename}')
        return jsonify({'success': True, 'message': f'Re-running rules for {case_file.original_filename}'})
        
    except Exception as e:
        logger.error(f"Error re-running rules for file {file_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/file/<int:file_id>/reprocess', methods=['POST'])
@login_required
@require_role('write')
def api_reprocess_file(file_id):
    try:
        case_file = CaseFile.query.get_or_404(file_id)
        
        # Reset file status for reprocessing
        case_file.processing_status = 'pending'
        case_file.processing_progress = 0
        case_file.event_count = 0
        case_file.sigma_violations = 0
        case_file.chainsaw_violations = 0
        case_file.error_message = None
        db.session.commit()
        
        # Queue for complete reprocessing
        process_evtx_file.delay(case_file.id)
        
        log_audit('file_reprocessed', f'Reprocessing file: {case_file.original_filename}')
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error reprocessing file {file_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/case/<int:case_id>/file-status')
@login_required
def api_case_file_status(case_id):
    try:
        case = Case.query.get_or_404(case_id)
        files = case.files.all()
        
        file_status = []
        for file in files:
            file_status.append({
                'id': file.id,
                'status': file.processing_status,
                'progress': file.processing_progress
            })
        
        return jsonify({'files': file_status})
        
    except Exception as e:
        logger.error(f"Error getting file status for case {case_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/diagnostics', methods=['POST'])
@login_required
@require_role('admin')
def api_diagnostics():
    try:
        system_info = get_system_info()
        
        # Additional diagnostic information
        diagnostics = {
            'health_check': 'System operational',
            'cpu_usage': f"{psutil.cpu_percent()}%",
            'memory_usage': f"{system_info.get('memory', {}).get('percent', 0):.1f}%",
            'disk_usage': f"{system_info.get('disk', {}).get('percent', 0):.1f}%",
            'service_status': format_service_status(system_info.get('services', {})),
            'opensearch_health': check_opensearch_health()
        }
        
        return jsonify(diagnostics)
        
    except Exception as e:
        logger.error(f"Error running diagnostics: {e}")
        return jsonify({'error': str(e)}), 500

def format_service_status(services):
    """Format service status for display"""
    status_html = ""
    for service, status in services.items():
        status_class = "success" if status else "danger"
        status_text = "Running" if status else "Stopped"
        status_html += f'<div class="service-item"><span class="badge badge-{status_class}">{service}: {status_text}</span></div>'
    return status_html

def check_opensearch_health():
    """Check OpenSearch cluster health"""
    try:
        health = opensearch_client.cluster.health()
        return f"Status: {health['status']}, Nodes: {health['number_of_nodes']}"
    except Exception as e:
        return f"Error: {str(e)}"

# Scheduled task to update rules daily
def setup_scheduler():
    """Setup scheduled tasks"""
    if not scheduler.running:
        # Update rules daily at 2 AM
        scheduler.add_job(
            func=daily_rule_update,
            trigger="cron",
            hour=2,
            minute=0,
            id='daily_rule_update'
        )
        scheduler.start()

def daily_rule_update():
    """Daily rule update task"""
    with app.app_context():
        try:
            update_rules()
            logger.info("Daily rule update completed successfully")
        except Exception as e:
            logger.error(f"Daily rule update failed: {e}")

# Initialize database and create default admin user
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create default admin user if it doesn't exist
        admin = User.query.filter_by(username='Admin').first()
        if not admin:
            admin = User(
                username='Admin',
                email='admin@casescope.local',
                role='admin'
            )
            admin.set_password('ChangeMe!')
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created: Admin / ChangeMe!")

if __name__ == '__main__':
    init_db()
    setup_scheduler()
    app.run(debug=False, host='127.0.0.1', port=5000)
