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
            for record in parser.records():
                try:
                    xml_data = record.xml()
                    event_data = xmltodict.parse(xml_data)
                    
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
                    
                    events.append(doc)
                    processed_records += 1
                    
                    # Update progress
                    progress = int((processed_records / total_records) * 80) + 10
                    case_file.processing_progress = progress
                    db.session.commit()
                    
                except Exception as e:
                    logger.error(f"Error processing record: {e}")
                    continue
            
            case_file.event_count = len(events)
            case_file.processing_progress = 90
            db.session.commit()
            
            # Apply rules (simplified for now)
            case_file.processing_status = 'completed'
            case_file.processing_progress = 100
            db.session.commit()
            
            logger.info(f"Successfully processed file {file_id} with {len(events)} events")
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
        
        for file in files[:5]:  # Limit to 5 files
            if file and file.filename:
                # Secure filename and create unique name
                original_filename = secure_filename(file.filename)
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
        
        flash(f'Successfully uploaded {len(uploaded_files)} file(s). Processing started.', 'success')
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
                search_body = {
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"case_id": case.id}},
                                {"multi_match": {
                                    "query": query,
                                    "fields": ["event_data.*", "source_file"]
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
                
                response = opensearch_client.search(
                    index=f"casescope-case-{case.id}",
                    body=search_body
                )
                
                results = response.get('hits', {}).get('hits', [])
                
            except Exception as e:
                logger.error(f"Search error: {e}")
                flash('Search error occurred.', 'error')
        
        return render_template('search.html', case=case, query=query, results=results)
    
    except Exception as e:
        logger.error(f"Error in search route: {e}")
        flash('Error accessing search functionality.', 'error')
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
    
    # Queue all files for rule re-run
    files = case.files.filter_by(processing_status='completed').all()
    for file in files:
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
        
        # Reset violation counts
        case_file.sigma_violations = 0
        case_file.chainsaw_violations = 0
        db.session.commit()
        
        # Queue for rules re-run (simplified - would need proper implementation)
        # In a full implementation, this would re-run only the rule analysis
        
        log_audit('rules_rerun', f'Re-running rules for file: {case_file.original_filename}')
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error re-running rules for file {file_id}: {e}")
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
