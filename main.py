#!/usr/bin/env python3
"""
caseScope 7.1.1 - Main Application Entry Point
Copyright (c) 2025 Justin Dube <casescope@thedubes.net>
"""

import os
import sys
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from datetime import datetime
from opensearchpy import OpenSearch
import re

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
    
    # Relationships
    creator = db.relationship('User', backref='created_cases')
    
    def __repr__(self):
        return f'<Case {self.case_number}: {self.name}>'
    
    @property
    def file_count(self):
        """Get number of files in this case"""
        return CaseFile.query.filter_by(case_id=self.id, is_deleted=False).count()
    
    @property
    def total_events(self):
        """Get total number of indexed events in this case"""
        # This will be implemented when we add event indexing
        return 0
    
    @property
    def storage_size(self):
        """Get total storage size for this case"""
        files = CaseFile.query.filter_by(case_id=self.id, is_deleted=False).all()
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
    indexing_status = db.Column(db.String(20), default='Uploaded')  # Uploaded, Indexing, Running Rules, Completed, Failed
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
    
    def __repr__(self):
        return f'<SigmaViolation Rule:{self.rule_id} File:{self.file_id}>'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

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
        user_count = User.query.count()
        case_count = Case.query.count()
        file_count = CaseFile.query.count()
        all_users = User.query.all()
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
        priority = request.form.get('priority', 'Medium')
        
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
                    case_number=case_number,
                    priority=priority,
                    created_by=current_user.id
                )
                db.session.add(new_case)
                db.session.commit()
                
                # Create case directory
                import os
                case_dir = f"/opt/casescope/uploads/{new_case.id}"
                os.makedirs(case_dir, exist_ok=True)
                
                # Set active case in session
                session['active_case_id'] = new_case.id
                
                flash(f'Case "{name}" created successfully!', 'success')
                return redirect(url_for('case_dashboard'))
                
            except Exception as e:
                db.session.rollback()
                flash(f'Error creating case: {str(e)}', 'error')
    
    return render_case_form()

@app.route('/case/select')
@login_required
def case_selection():
    """Case selection page"""
    cases = Case.query.filter_by(is_active=True).order_by(Case.updated_at.desc()).all()
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

@app.route('/case/dashboard')
@login_required
def case_dashboard():
    """Case-specific dashboard"""
    active_case_id = session.get('active_case_id')
    if not active_case_id:
        flash('Please select a case first.', 'warning')
        return redirect(url_for('case_selection'))
    
    case = db.session.get(Case, active_case_id)
    if not case:
        flash('Case not found.', 'error')
        return redirect(url_for('case_selection'))
    
    # Get case-specific statistics
    total_files = CaseFile.query.filter_by(case_id=case.id, is_deleted=False).count()
    indexed_files = CaseFile.query.filter_by(case_id=case.id, is_deleted=False, is_indexed=True).count()
    processing_files = CaseFile.query.filter_by(case_id=case.id, is_deleted=False).filter(
        CaseFile.indexing_status.in_(['Counting Events', 'Indexing', 'Running Rules', 'Preparing to Index'])
    ).count()
    total_events = db.session.query(db.func.sum(CaseFile.event_count)).filter_by(case_id=case.id, is_deleted=False).scalar() or 0
    total_violations = db.session.query(db.func.sum(CaseFile.violation_count)).filter_by(case_id=case.id, is_deleted=False).scalar() or 0
    total_storage = db.session.query(db.func.sum(CaseFile.file_size)).filter_by(case_id=case.id, is_deleted=False).scalar() or 0
    
    return render_case_dashboard(case, total_files, indexed_files, processing_files, total_events, total_violations, total_storage)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_files():
    """File upload for active case"""
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
                duplicate = CaseFile.query.filter_by(
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
                
                # Create database record
                case_file = CaseFile(
                    case_id=case.id,
                    filename=safe_filename,
                    original_filename=file.filename,
                    file_path=file_path,
                    file_size=file_size,
                    file_hash=sha256_hash,
                    mime_type=mime_type,
                    uploaded_by=current_user.id,
                    indexing_status='Uploaded'
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
                
                # Trigger background indexing for each uploaded file
                try:
                    # Get the files we just uploaded
                    recent_files = CaseFile.query.filter_by(
                        case_id=case.id,
                        indexing_status='Uploaded'
                    ).order_by(CaseFile.uploaded_at.desc()).limit(success_count).all()
                    
                    for uploaded_file in recent_files:
                        if celery_app:
                            celery_app.send_task(
                                'tasks.start_file_indexing',
                                args=[uploaded_file.id],
                                queue='celery',
                                priority=0,
                            )
                            print(f"[Upload] Queued indexing for file ID {uploaded_file.id}: {uploaded_file.original_filename}")
                        else:
                            print(f"[Upload] WARNING: Celery not available, task not queued for file ID {uploaded_file.id}")
                    
                    flash(f'Successfully uploaded {success_count} file(s). Indexing started.', 'success')
                except Exception as e:
                    print(f"[Upload] Warning: Failed to queue indexing tasks: {e}")
                    flash(f'Successfully uploaded {success_count} file(s). Manual indexing may be required.', 'warning')
                
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

@app.route('/files')
@login_required
def list_files():
    """List files in active case"""
    active_case_id = session.get('active_case_id')
    if not active_case_id:
        flash('Please select a case first.', 'warning')
        return redirect(url_for('case_selection'))
    
    case = db.session.get(Case, active_case_id)
    if not case:
        flash('Case not found.', 'error')
        return redirect(url_for('case_selection'))
    files = CaseFile.query.filter_by(case_id=case.id, is_deleted=False).order_by(CaseFile.uploaded_at.desc()).all()
    
    return render_file_list(case, files)


@app.route('/file/reindex/<int:file_id>', methods=['POST'])
@login_required
def reindex_file(file_id):
    """Re-index a file (discard existing index and re-process)"""
    case_file = CaseFile.query.get_or_404(file_id)
    
    # Verify file belongs to active case
    active_case_id = session.get('active_case_id')
    if not active_case_id or case_file.case_id != active_case_id:
        flash('Access denied.', 'error')
        return redirect(url_for('list_files'))
    
    try:
        # Reset file status
        case_file.indexing_status = 'Uploaded'
        case_file.is_indexed = False
        case_file.indexed_at = None
        case_file.event_count = 0
        case_file.violation_count = 0
        db.session.commit()
        
        # Queue indexing task
        try:
            if celery_app:
                celery_app.send_task(
                    'tasks.start_file_indexing',
                    args=[file_id],
                    queue='celery',
                    priority=0,
                )
                flash(f'Re-indexing started for {case_file.original_filename}', 'success')
                print(f"[Re-index] Queued re-indexing for file ID {file_id}: {case_file.original_filename}")
            else:
                flash(f'Celery worker not available', 'error')
                print(f"[Re-index] ERROR: Celery not available for file ID {file_id}")
        except Exception as e:
            print(f"[Re-index] Error queuing task: {e}")
            flash(f'Re-index queued but worker may not be running. Check logs.', 'warning')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error re-indexing file: {str(e)}', 'error')
        print(f"[Re-index] Database error: {e}")
    
    return redirect(url_for('list_files'))


@app.route('/file/rerun-rules/<int:file_id>', methods=['POST'])
@login_required
def rerun_rules(file_id):
    """Re-run SIGMA rules on a file (discard existing violations and re-process)"""
    case_file = CaseFile.query.get_or_404(file_id)
    
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
        # Delete existing violations for this file
        existing_violations = SigmaViolation.query.filter_by(file_id=file_id).all()
        if existing_violations:
            print(f"[Re-run Rules] Deleting {len(existing_violations)} existing violations for file ID {file_id}")
            for violation in existing_violations:
                db.session.delete(violation)
        
        # Reset violation status
        case_file.indexing_status = 'Running Rules'
        case_file.violation_count = 0
        db.session.commit()
        print(f"[Re-run Rules] Reset status to 'Running Rules' for file ID {file_id}")
        
        # Queue SIGMA rule processing
        try:
            # Import shared index name helper
            from tasks import make_index_name
            
            # Generate index name using shared helper (single source of truth)
            index_name = make_index_name(case_file.case_id, case_file.original_filename)
            
            print(f"[Re-run Rules] DEBUG: celery_app exists: {celery_app is not None}")
            if celery_app:
                print(f"[Re-run Rules] DEBUG: celery_app broker: {celery_app.conf.broker_url}")
                print(f"[Re-run Rules] DEBUG: celery_app backend: {celery_app.conf.result_backend}")
                print(f"[Re-run Rules] DEBUG: Calling send_task with task='tasks.process_sigma_rules', args=[{file_id}, '{index_name}']")
                
                # Use send_task with the SHARED celery_app (same instance as worker)
                task = celery_app.send_task(
                    'tasks.process_sigma_rules',
                    args=[file_id, index_name],
                    queue='celery',
                    priority=0,  # Force single list key
                )
                
                # Save task ID for progress tracking
                case_file.celery_task_id = task.id
                db.session.commit()
                print(f"[Re-run Rules] Queued task ID: {task.id}, saved to DB")
                
                flash(f'Re-running SIGMA rules for {case_file.original_filename}', 'success')
                print(f"[Re-run Rules] Queued rule processing task {task.id} for file ID {file_id}: {case_file.original_filename}, index: {index_name}")
                
                # Check Redis queue
                try:
                    import redis
                    r = redis.Redis(host='localhost', port=6379, db=0)
                    queue_length = r.llen('celery')
                    print(f"[Re-run Rules] DEBUG: Redis queue 'celery' length: {queue_length}")
                except Exception as redis_err:
                    print(f"[Re-run Rules] DEBUG: Could not check Redis: {redis_err}")
            else:
                flash(f'Celery worker not available', 'error')
                print(f"[Re-run Rules] ERROR: Celery not available for file ID {file_id}")
        except Exception as e:
            print(f"[Re-run Rules] Error queuing task: {e}")
            import traceback
            traceback.print_exc()
            flash(f'Rule processing queued but worker may not be running. Check logs.', 'warning')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error re-running rules: {str(e)}', 'error')
        print(f"[Re-run Rules] Database error: {e}")
    
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
        files = CaseFile.query.filter_by(case_id=case_id, is_deleted=False).all()
        
        if not files:
            return jsonify({'success': False, 'message': 'No files found in this case'}), 404
        
        files_queued = 0
        for case_file in files:
            try:
                # Reset file status
                case_file.indexing_status = 'Uploaded'
                case_file.is_indexed = False
                case_file.indexed_at = None
                case_file.event_count = 0
                case_file.violation_count = 0
                db.session.commit()
                
                # Queue indexing task
                if celery_app:
                    celery_app.send_task(
                        'tasks.start_file_indexing',
                        args=[case_file.id],
                        queue='celery',
                        priority=0,
                    )
                    files_queued += 1
                    print(f"[Bulk Re-index] Queued file ID {case_file.id}: {case_file.original_filename}")
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
        files = CaseFile.query.filter_by(case_id=case_id, is_deleted=False, is_indexed=True).all()
        
        if not files:
            return jsonify({'success': False, 'message': 'No indexed files found in this case'}), 404
        
        files_queued = 0
        for case_file in files:
            try:
                # Delete existing violations for this file
                existing_violations = SigmaViolation.query.filter_by(file_id=case_file.id).all()
                if existing_violations:
                    print(f"[Bulk Re-run Rules] Deleting {len(existing_violations)} violations for file ID {case_file.id}")
                    for violation in existing_violations:
                        db.session.delete(violation)
                
                # Reset violation status
                case_file.indexing_status = 'Running Rules'
                case_file.violation_count = 0
                db.session.commit()
                
                # Queue SIGMA rule processing
                if celery_app:
                    from tasks import make_index_name
                    index_name = make_index_name(case_file.case_id, case_file.original_filename)
                    
                    celery_app.send_task(
                        'tasks.process_sigma_rules',
                        args=[index_name, case_file.id],
                        queue='celery',
                        priority=0,
                    )
                    files_queued += 1
                    print(f"[Bulk Re-run Rules] Queued file ID {case_file.id}: {case_file.original_filename}")
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

@app.route('/update-event-ids', methods=['GET'])
@login_required
def update_event_ids():
    """Update Event ID database (placeholder for future enhancement)"""
    flash('Event ID database is already up to date with 100+ Windows Event IDs. If you download new Event IDs, re-index all files to apply the new descriptions.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/violations', methods=['GET'])
@login_required
def violations():
    """View SIGMA rule violations for active case"""
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
    query = SigmaViolation.query.filter_by(case_id=case_id)
    
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
    all_rules = SigmaRule.query.join(SigmaViolation).filter(SigmaViolation.case_id == case_id).distinct().all()
    all_files = CaseFile.query.join(SigmaViolation).filter(SigmaViolation.case_id == case_id).distinct().all()
    
    # Get statistics
    total_violations = SigmaViolation.query.filter_by(case_id=case_id).count()
    critical_count = SigmaViolation.query.filter_by(case_id=case_id, severity='critical').count()
    high_count = SigmaViolation.query.filter_by(case_id=case_id, severity='high').count()
    medium_count = SigmaViolation.query.filter_by(case_id=case_id, severity='medium').count()
    low_count = SigmaViolation.query.filter_by(case_id=case_id, severity='low').count()
    reviewed_count = SigmaViolation.query.filter_by(case_id=case_id, is_reviewed=True).count()
    
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
    violation = SigmaViolation.query.get(violation_id)
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

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    """Search indexed events in active case"""
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
    
    # Get all indexed files for this case to determine which indices to search
    indexed_files = CaseFile.query.filter_by(case_id=case.id, is_indexed=True, is_deleted=False).all()
    
    if not indexed_files:
        flash('No indexed files in this case. Upload and index files first.', 'warning')
        return redirect(url_for('list_files'))
    
    # Build list of indices to search using shared helper
    from tasks import make_index_name
    indices = []
    for file in indexed_files:
        index_name = make_index_name(case.id, file.original_filename)
        indices.append(index_name)
    
    results = []
    total_hits = 0
    query_str = ""
    error_message = None
    page = 1
    per_page = 50
    violations_only = False
    
    if request.method == 'POST':
        query_str = request.form.get('query', '').strip()
        page = int(request.form.get('page', 1))
        violations_only = request.form.get('violations_only') == 'true'
        
        if query_str:
            try:
                # Build OpenSearch query from user input (this transforms the query)
                # But we keep query_str unchanged for display
                base_query = build_opensearch_query(query_str)
                
                # NEW IN v7.2.0: Filter for SIGMA violations if checkbox checked
                if violations_only:
                    os_query = {
                        "bool": {
                            "must": [
                                base_query,
                                {"exists": {"field": "has_violations"}}
                            ]
                        }
                    }
                else:
                    os_query = base_query
                
                # Search across all indices for this case
                from_offset = (page - 1) * per_page
                search_body = {
                    "query": os_query,
                    "from": from_offset,
                    "size": per_page,
                    # Sort by timestamp (newest first) using the .date subfield
                    # Falls back to relevance score if timestamp unavailable
                    "sort": [
                        {"System.TimeCreated.@SystemTime.date": {"order": "desc", "unmapped_type": "date"}},
                        "_score"
                    ],
                    "_source": True
                }
                
                response = opensearch_client.search(
                    index=','.join(indices),
                    body=search_body
                )
                
                total_hits = response['hits']['total']['value']
                
                for hit in response['hits']['hits']:
                    source = hit['_source']
                    
                    # Get timestamp from various possible fields (XML attribute notation)
                    timestamp = source.get('System.TimeCreated.@SystemTime') or \
                               source.get('System.TimeCreated.SystemTime') or \
                               source.get('System_TimeCreated_SystemTime') or \
                               source.get('@timestamp') or \
                               'N/A'
                    
                    # Get Event ID (XML text node notation)
                    event_id = source.get('System.EventID.#text') or \
                              source.get('System.EventID') or \
                              source.get('System_EventID') or \
                              source.get('EventID') or \
                              'N/A'
                    
                    # Get source filename from metadata
                    metadata = source.get('_casescope_metadata', {})
                    source_file = metadata.get('filename', 'Unknown')
                    
                    # Get computer name
                    computer = source.get('System.Computer') or \
                              source.get('System_Computer') or \
                              source.get('Computer') or \
                              'N/A'
                    
                    # Get channel
                    channel = source.get('System.Channel') or \
                             source.get('System_Channel') or \
                             'N/A'
                    
                    # Get provider (XML attribute notation)
                    provider = source.get('System.Provider.@Name') or \
                              source.get('System.Provider.Name') or \
                              source.get('System_Provider_Name') or \
                              'N/A'
                    
                    # Get event description
                    event_description = get_event_description(event_id, channel, provider, source)
                    
                    # Get SIGMA violations if present
                    sigma_violations = source.get('sigma_detections', [])
                    has_violations = source.get('has_violations', False)
                    
                    results.append({
                        'index': hit['_index'],
                        'id': hit['_id'],
                        'score': hit['_score'],
                        'timestamp': timestamp,
                        'event_id': event_id,
                        'event_type': event_description,
                        'source_file': source_file,
                        'computer': computer,
                        'channel': channel,
                        'provider': provider,
                        'full_data': source,
                        'sigma_violations': sigma_violations,
                        'has_violations': has_violations
                    })
                
            except Exception as e:
                import traceback
                error_message = f"Search error: {str(e)}"
                print(f"[Search] Error: {e}")
                traceback.print_exc()
    
    return render_search_page(case, query_str, results, total_hits, page, per_page, error_message, len(indexed_files), violations_only)

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
                                existing = SigmaRule.query.filter_by(rule_hash=rule_hash).first()
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
            enabled_count = SigmaRule.query.filter_by(is_enabled=True).count()
            
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
                existing = SigmaRule.query.filter_by(rule_hash=rule_hash).first()
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
            rule = SigmaRule.query.get(rule_id)
            if rule:
                rule.is_enabled = not rule.is_enabled
                db.session.commit()
                status = 'enabled' if rule.is_enabled else 'disabled'
                flash(f'Rule {status}: {rule.title}', 'success')
            return redirect(url_for('sigma_rules'))
        
        elif action == 'delete':
            # Delete user-uploaded rule (not built-in)
            rule_id = request.form.get('rule_id')
            rule = SigmaRule.query.get(rule_id)
            if rule and not rule.is_builtin:
                db.session.delete(rule)
                db.session.commit()
                flash(f'Rule deleted: {rule.title}', 'success')
            elif rule and rule.is_builtin:
                flash('Cannot delete built-in rules', 'error')
            return redirect(url_for('sigma_rules'))
    
    # GET request - show all rules (search is client-side JavaScript)
    all_rules = SigmaRule.query.order_by(SigmaRule.is_builtin.desc(), SigmaRule.level.desc(), SigmaRule.title).all()
    enabled_count = SigmaRule.query.filter_by(is_enabled=True).count()
    total_count = SigmaRule.query.count()
    
    # Get violation statistics
    total_violations = SigmaViolation.query.count()
    critical_violations = SigmaViolation.query.join(SigmaRule).filter(SigmaRule.level == 'critical').count()
    high_violations = SigmaViolation.query.join(SigmaRule).filter(SigmaRule.level == 'high').count()
    
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
        
            <h3 class="menu-title">Management</h3>
            <a href="/case-management" class="menu-item placeholder">⚙️ Case Management (Coming Soon)</a>
            <a href="/file-management" class="menu-item placeholder">🗂️ File Management (Coming Soon)</a>
            <a href="/users" class="menu-item placeholder">👥 User Management (Coming Soon)</a>
            <a href="/sigma-rules" class="menu-item {'active' if active_page == 'sigma_rules' else ''}">📋 SIGMA Rules</a>
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
    # EventID is indexed as both text (System_EventID_#text) and keyword (System_EventID_#text.keyword)
    field_mappings = {
        'EventID': 'System_EventID_#text',
        'Computer': 'System_Computer',
        'Channel': 'System_Channel',
        'Provider': 'System_Provider_@Name',
        'Level': 'System_Level',
        'Task': 'System_Task',
        'TimeCreated': 'System_TimeCreated_@SystemTime',
        'source_filename': '_casescope_metadata_filename',
        'filename': '_casescope_metadata_filename'  # Alternative field name
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
            user_count = User.query.count()
            print(f"DEBUG: Total users in database: {user_count}")
            
            # Look for the user
            user = User.query.filter(db.func.lower(User.username) == username).first()
            print(f"DEBUG: User found: {user is not None}")
            
            if user:
                print(f"DEBUG: User details - ID: {user.id}, Username: {user.username}, Active: {user.is_active}")
                password_valid = user.check_password(password)
                print(f"DEBUG: Password valid: {password_valid}")
                
                if password_valid and user.is_active:
                    login_user(user)
                    print(f"DEBUG: User logged in successfully")
                    if user.force_password_change:
                        flash('You must change your password before continuing.', 'warning')
                        return redirect(url_for('change_password'))
                    return redirect(url_for('dashboard'))
                else:
                    print(f"DEBUG: Login failed - Password valid: {password_valid}, User active: {user.is_active}")
                    flash('Invalid username or password.', 'error')
            else:
                print(f"DEBUG: No user found with username: '{username}'")
                # List all users for debugging
                all_users = User.query.all()
                print(f"DEBUG: All users in database: {[u.username for u in all_users]}")
                flash('Invalid username or password.', 'error')
                
        except Exception as e:
            print(f"DEBUG: Database error during login: {e}")
            import traceback
            traceback.print_exc()
            flash('Database error. Please check system logs.', 'error')
    
    # Flash messages for display
    flash_messages = ""
    if hasattr(session, '_flashes') and session._flashes:
        for category, message in session._flashes:
            flash_messages += f'<div class="alert alert-{category}">{message}</div>'
        session._flashes.clear()
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>caseScope 7.1 - Login</title>
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #1a237e 0%, #3949ab 100%); 
                color: white; 
                margin: 0; 
                padding: 0; 
                min-height: 100vh; 
                display: flex; 
                align-items: center; 
                justify-content: center;
            }}
            .login-container {{ 
                max-width: 420px; 
                width: 90%; 
                background: linear-gradient(145deg, #283593, #1e88e5); 
                padding: 30px; 
                border-radius: 20px; 
                box-shadow: 
                    0 20px 40px rgba(0,0,0,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .logo {{ 
                text-align: center; 
                font-size: 3em; 
                margin-bottom: 30px; 
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                font-weight: 300;
            }}
            .logo .case {{ color: #4caf50; }}
            .logo .scope {{ color: white; }}
            .form-group {{
                margin-bottom: 18px;
            }}
            input {{ 
                width: 100%; 
                padding: 15px 20px; 
                margin: 0; 
                border: none; 
                border-radius: 12px; 
                background: rgba(255,255,255,0.1);
                color: white;
                font-size: 16px;
                box-shadow: 
                    inset 0 2px 5px rgba(0,0,0,0.2),
                    0 1px 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(5px);
                border: 1px solid rgba(255,255,255,0.1);
                box-sizing: border-box;
            }}
            input::placeholder {{
                color: rgba(255,255,255,0.7);
            }}
            input:focus {{
                outline: none;
                box-shadow: 
                    inset 0 2px 5px rgba(0,0,0,0.2),
                    0 0 0 3px rgba(76,175,80,0.3);
                border-color: #4caf50;
            }}
            button {{ 
                width: 100%; 
                padding: 15px; 
                background: linear-gradient(145deg, #4caf50, #388e3c); 
                color: white; 
                border: none; 
                border-radius: 12px; 
                cursor: pointer; 
                font-size: 16px;
                font-weight: 600;
                box-shadow: 
                    0 8px 15px rgba(76,175,80,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.2);
                transition: all 0.3s ease;
            }}
            button:hover {{
                background: linear-gradient(145deg, #66bb6a, #4caf50);
                box-shadow: 
                    0 12px 20px rgba(76,175,80,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.2);
                transform: translateY(-2px);
            }}
            button:active {{
                transform: translateY(0);
                box-shadow: 
                    0 4px 8px rgba(76,175,80,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.2);
            }}
            .version {{ 
                text-align: center; 
                margin-top: 30px; 
                font-size: 0.9em; 
                color: rgba(255,255,255,0.7); 
                text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
            }}
            .alert {{
                padding: 12px 16px;
                margin-bottom: 20px;
                border-radius: 8px;
                font-size: 14px;
            }}
            .alert-error {{
                background: linear-gradient(145deg, #f44336, #d32f2f);
                border: 1px solid rgba(255,255,255,0.1);
                box-shadow: 0 4px 8px rgba(244,67,54,0.3);
            }}
            .alert-info {{
                background: linear-gradient(145deg, #2196f3, #1976d2);
                border: 1px solid rgba(255,255,255,0.1);
                box-shadow: 0 4px 8px rgba(33,150,243,0.3);
            }}
        </style>
    </head>
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
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get real system statistics
    total_cases = Case.query.count()
    total_files = CaseFile.query.filter_by(is_deleted=False).count()
    total_indexed = CaseFile.query.filter_by(is_deleted=False, is_indexed=True).count()
    total_events = db.session.query(db.func.sum(CaseFile.event_count)).filter_by(is_deleted=False).scalar() or 0
    total_storage = db.session.query(db.func.sum(CaseFile.file_size)).filter_by(is_deleted=False).scalar() or 0
    total_violations = db.session.query(db.func.sum(CaseFile.violation_count)).filter_by(is_deleted=False).scalar() or 0
    
    # Get user count
    total_users = User.query.count()
    
    # Recent activity
    recent_cases = Case.query.order_by(Case.created_at.desc()).limit(5).all()
    recent_files = CaseFile.query.filter_by(is_deleted=False).order_by(CaseFile.uploaded_at.desc()).limit(5).all()
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>caseScope 7.2 - Dashboard</title>
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #1a237e 0%, #3949ab 100%); 
                color: white; 
                margin: 0; 
                display: flex; 
                min-height: 100vh; 
            }}
            .sidebar {{ 
                width: 280px; 
                background: linear-gradient(145deg, #303f9f, #283593); 
                padding: 20px; 
                box-shadow: 
                    5px 0 20px rgba(0,0,0,0.4),
                    inset -1px 0 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
            }}
            .main-content {{ flex: 1; }}
            .header {{ 
                background: linear-gradient(145deg, #283593, #1e88e5); 
                padding: 15px 30px; 
                display: flex; 
                justify-content: flex-end; 
                align-items: center;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                border-bottom: 1px solid rgba(255,255,255,0.1);
                min-height: 60px;
            }}
            .user-info {{ 
                display: flex; 
                align-items: center; 
                gap: 20px;
                font-size: 1em;
                line-height: 1.2;
            }}
            .sidebar-logo {{
                text-align: center;
                font-size: 2.2em;
                font-weight: 300;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                margin-bottom: 15px;
                padding: 5px 0 8px 0;
                border-bottom: 1px solid rgba(76,175,80,0.3);
            }}
            .sidebar-logo .case {{ color: #4caf50; }}
            .sidebar-logo .scope {{ color: white; }}
            .version-badge {{
                font-size: 0.4em;
                background: linear-gradient(145deg, #4caf50, #388e3c);
                color: white;
                padding: 3px 6px;
                border-radius: 6px;
                margin-top: 5px;
                display: inline-block;
                box-shadow: 0 2px 4px rgba(76,175,80,0.3);
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .content {{ padding: 30px; }}
            .tile {{ 
                background: linear-gradient(145deg, #3f51b5, #283593); 
                padding: 30px; 
                margin: 0; 
                border-radius: 15px; 
                box-shadow: 
                    0 10px 25px rgba(0,0,0,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255,255,255,0.1);
                transition: all 0.3s ease;
            }}
            .tile:hover {{
                transform: translateY(-5px);
                box-shadow: 
                    0 20px 40px rgba(0,0,0,0.5),
                    inset 0 1px 0 rgba(255,255,255,0.1);
            }}
            .tile h3 {{
                margin-top: 0;
                margin-bottom: 20px;
                font-size: 1.3em;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
            }}
            .tiles {{ 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); 
                gap: 30px; 
            }}
            .menu-item {{ 
                display: block; 
                color: white; 
                text-decoration: none; 
                padding: 12px 16px; 
                margin: 6px 0; 
                border-radius: 12px; 
                background: linear-gradient(145deg, #3949ab, #283593);
                box-shadow: 
                    0 4px 8px rgba(0,0,0,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.1);
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
                font-size: 0.95em;
            }}
            .menu-item:hover {{ 
                background: linear-gradient(145deg, #5c6bc0, #3949ab);
                transform: translateX(5px);
                box-shadow: 
                    0 8px 15px rgba(0,0,0,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.2);
            }}
            .menu-item.placeholder {{ 
                background: linear-gradient(145deg, #424242, #2e2e2e); 
                color: #aaa; 
                cursor: not-allowed;
                opacity: 0.7;
            }}
            .menu-item.placeholder:hover {{
                transform: none;
                box-shadow: 
                    0 4px 8px rgba(0,0,0,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.1);
            }}
            h3.menu-title {{
                font-size: 1.1em;
                margin: 15px 0 8px 0;
                color: #4caf50;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
                border-bottom: 1px solid rgba(76,175,80,0.3);
                padding-bottom: 4px;
            }}
            a {{ color: #4caf50; text-decoration: none; transition: color 0.3s ease; }}
            a:hover {{ color: #66bb6a; }}
            .logout-btn {{
                background: linear-gradient(145deg, #f44336, #d32f2f);
                color: white !important;
                padding: 8px 16px;
                border-radius: 8px;
                text-decoration: none;
                font-size: 0.9em;
                font-weight: 500;
                box-shadow: 0 4px 8px rgba(244,67,54,0.3);
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .logout-btn:hover {{
                background: linear-gradient(145deg, #ef5350, #f44336);
                box-shadow: 0 6px 12px rgba(244,67,54,0.4);
                transform: translateY(-1px);
                color: white !important;
            }}
            .logout-btn:active {{
                transform: translateY(0);
                box-shadow: 0 2px 4px rgba(244,67,54,0.3);
            }}
            .footer {{ 
                position: fixed; 
                bottom: 15px; 
                right: 20px; 
                font-size: 0.85em; 
                color: rgba(255,255,255,0.7);
                text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
            }}
            .status {{ 
                display: inline-block; 
                padding: 6px 12px; 
                border-radius: 8px; 
                font-size: 0.85em;
                font-weight: 500;
                box-shadow: 0 2px 4px rgba(0,0,0,0.3);
                margin: 2px 0;
            }}
            .status.operational {{ 
                background: linear-gradient(145deg, #4caf50, #388e3c);
                color: white;
            }}
            .status.placeholder {{ 
                background: linear-gradient(145deg, #ff9800, #f57c00);
                color: white;
            }}
            .success-banner {{
                background: linear-gradient(145deg, #2e7d32, #1b5e20);
                padding: 25px;
                border-radius: 15px;
                margin-top: 30px;
                box-shadow: 
                    0 8px 20px rgba(46,125,50,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.1);
                border: 1px solid rgba(76,175,80,0.3);
            }}
            .success-banner h3 {{
                margin-top: 0;
                color: #4caf50;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
            }}
        </style>
    </head>
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
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="{url_for('logout')}" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                <h1>🎯 System Dashboard</h1>
                <div class="tiles">
                    <div class="tile">
                        <h3>📈 System Statistics</h3>
                        <p><strong>Total Cases:</strong> {total_cases:,}</p>
                        <p><strong>Total Files:</strong> {total_files:,} ({total_indexed:,} indexed)</p>
                        <p><strong>Total Events:</strong> {total_events:,}</p>
                        <p><strong>Total Users:</strong> {total_users}</p>
                    </div>
                    <div class="tile">
                        <h3>💾 Storage & Analysis</h3>
                        <p><strong>Storage Used:</strong> {total_storage / (1024*1024*1024):.2f} GB</p>
                        <p><strong>Indexed Files:</strong> {total_indexed:,} / {total_files:,}</p>
                        <p><strong>SIGMA Violations:</strong> {total_violations:,}</p>
                        <p><strong>Processing:</strong> <span class="status operational">✓ Active</span></p>
                    </div>
                    <div class="tile">
                        <h3>🔧 System Status</h3>
                        <p><span class="status operational">✓ OpenSearch: Running</span></p>
                        <p><span class="status operational">✓ Redis: Running</span></p>
                        <p><span class="status operational">✓ Celery Worker: Running</span></p>
                        <p><span class="status operational">✓ Web Server: Running</span></p>
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
    </body>
    </html>
    '''

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
    
    # Flash messages for display
    flash_messages = ""
    if hasattr(session, '_flashes') and session._flashes:
        for category, message in session._flashes:
            flash_messages += f'<div class="alert alert-{category}">{message}</div>'
        session._flashes.clear()
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Change Password - caseScope 7.1</title>
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #1a237e 0%, #3949ab 100%); 
                color: white; 
                margin: 0; 
                padding: 0; 
                min-height: 100vh; 
                display: flex; 
                align-items: center; 
                justify-content: center;
            }}
            .container {{ 
                max-width: 500px; 
                width: 90%; 
                background: linear-gradient(145deg, #283593, #1e88e5); 
                padding: 30px; 
                border-radius: 20px; 
                box-shadow: 
                    0 20px 40px rgba(0,0,0,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .logo {{ 
                text-align: center; 
                font-size: 3em; 
                margin-bottom: 30px; 
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                font-weight: 300;
            }}
            .logo .case {{ color: #4caf50; }}
            .logo .scope {{ color: white; }}
            h2 {{
                text-align: center;
                margin-bottom: 10px;
                font-weight: 300;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
            }}
            p {{
                text-align: center;
                margin-bottom: 25px;
                color: rgba(255,255,255,0.8);
                font-size: 0.95em;
            }}
            .form-group {{
                margin-bottom: 18px;
            }}
            input {{ 
                width: 100%; 
                padding: 15px 20px; 
                margin: 0; 
                border: none; 
                border-radius: 12px; 
                background: rgba(255,255,255,0.1);
                color: white;
                font-size: 16px;
                box-shadow: 
                    inset 0 2px 5px rgba(0,0,0,0.2),
                    0 1px 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(5px);
                border: 1px solid rgba(255,255,255,0.1);
                box-sizing: border-box;
            }}
            input::placeholder {{
                color: rgba(255,255,255,0.7);
            }}
            input:focus {{
                outline: none;
                box-shadow: 
                    inset 0 2px 5px rgba(0,0,0,0.2),
                    0 0 0 3px rgba(76,175,80,0.3);
                border-color: #4caf50;
            }}
            button {{ 
                width: 100%; 
                padding: 15px; 
                background: linear-gradient(145deg, #4caf50, #388e3c); 
                color: white; 
                border: none; 
                border-radius: 12px; 
                cursor: pointer; 
                font-size: 16px;
                font-weight: 600;
                box-shadow: 
                    0 8px 15px rgba(76,175,80,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.2);
                transition: all 0.3s ease;
                margin-top: 10px;
            }}
            button:hover {{
                background: linear-gradient(145deg, #66bb6a, #4caf50);
                box-shadow: 
                    0 12px 20px rgba(76,175,80,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.2);
                transform: translateY(-2px);
            }}
            button:active {{
                transform: translateY(0);
                box-shadow: 
                    0 4px 8px rgba(76,175,80,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.2);
            }}
            .alert {{
                padding: 12px 16px;
                margin-bottom: 20px;
                border-radius: 8px;
                font-size: 14px;
            }}
            .alert-error {{
                background: linear-gradient(145deg, #f44336, #d32f2f);
                border: 1px solid rgba(255,255,255,0.1);
                box-shadow: 0 4px 8px rgba(244,67,54,0.3);
            }}
            .alert-success {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
                border: 1px solid rgba(255,255,255,0.1);
                box-shadow: 0 4px 8px rgba(76,175,80,0.3);
            }}
            .alert-warning {{
                background: linear-gradient(145deg, #ff9800, #f57c00);
                border: 1px solid rgba(255,255,255,0.1);
                box-shadow: 0 4px 8px rgba(255,152,0,0.3);
            }}
        </style>
    </head>
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
    """Render file upload form"""
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
        <title>Upload Files - {case.name} - caseScope 7.1</title>
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #1a237e 0%, #3949ab 100%); 
                color: white; 
                margin: 0; 
                display: flex; 
                min-height: 100vh; 
            }}
            .sidebar {{ 
                width: 280px; 
                background: linear-gradient(145deg, #303f9f, #283593); 
                padding: 20px; 
                box-shadow: 
                    5px 0 20px rgba(0,0,0,0.4),
                    inset -1px 0 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
            }}
            .main-content {{ flex: 1; }}
            .header {{ 
                background: linear-gradient(145deg, #283593, #1e88e5); 
                padding: 15px 30px; 
                display: flex; 
                justify-content: space-between; 
                align-items: center;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                border-bottom: 1px solid rgba(255,255,255,0.1);
                min-height: 60px;
            }}
            .case-title {{
                font-size: 1.3em;
                font-weight: 600;
            }}
            .user-info {{ 
                display: flex; 
                align-items: center; 
                gap: 20px;
                font-size: 1em;
                line-height: 1.2;
            }}
            .sidebar-logo {{
                text-align: center;
                font-size: 2.2em;
                font-weight: 300;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                margin-bottom: 15px;
                padding: 5px 0 8px 0;
                border-bottom: 1px solid rgba(76,175,80,0.3);
            }}
            .sidebar-logo .case {{ color: #4caf50; }}
            .sidebar-logo .scope {{ color: white; }}
            .version-badge {{
                font-size: 0.4em;
                background: linear-gradient(145deg, #4caf50, #388e3c);
                color: white;
                padding: 3px 6px;
                border-radius: 6px;
                margin-top: 5px;
                display: inline-block;
                box-shadow: 0 2px 4px rgba(76,175,80,0.3);
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .content {{ padding: 30px; }}
            .menu-item {{ 
                display: block; 
                color: white; 
                text-decoration: none; 
                padding: 12px 16px; 
                margin: 6px 0; 
                border-radius: 12px; 
                background: linear-gradient(145deg, #3949ab, #283593);
                box-shadow: 
                    0 4px 8px rgba(0,0,0,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.1);
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
                font-size: 0.95em;
            }}
            .menu-item:hover {{ 
                background: linear-gradient(145deg, #5c6bc0, #3949ab);
                transform: translateX(5px);
                box-shadow: 
                    0 8px 15px rgba(0,0,0,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.2);
            }}
            .menu-item.active {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
            }}
            .menu-item.placeholder {{ 
                background: linear-gradient(145deg, #424242, #2e2e2e); 
                color: #aaa; 
                cursor: not-allowed;
                opacity: 0.7;
            }}
            .menu-item.placeholder:hover {{
                transform: none;
                box-shadow: 
                    0 4px 8px rgba(0,0,0,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.1);
            }}
            h3.menu-title {{
                font-size: 1.1em;
                margin: 15px 0 8px 0;
                color: #4caf50;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
                border-bottom: 1px solid rgba(76,175,80,0.3);
                padding-bottom: 4px;
            }}
            .logout-btn {{
                background: linear-gradient(145deg, #f44336, #d32f2f);
                color: white !important;
                padding: 8px 16px;
                border-radius: 8px;
                text-decoration: none;
                font-size: 0.9em;
                font-weight: 500;
                box-shadow: 0 4px 8px rgba(244,67,54,0.3);
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .logout-btn:hover {{
                background: linear-gradient(145deg, #ef5350, #f44336);
                box-shadow: 0 6px 12px rgba(244,67,54,0.4);
                transform: translateY(-1px);
                color: white !important;
            }}
            .upload-container {{
                background: linear-gradient(145deg, #283593, #1e88e5);
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 8px 20px rgba(0,0,0,0.3);
                max-width: 95%;
                margin: 0 auto;
            }}
            .file-input {{
                display: block;
                width: 100%;
                padding: 20px;
                border: 2px dashed rgba(255,255,255,0.3);
                border-radius: 10px;
                background: rgba(255,255,255,0.05);
                cursor: pointer;
                text-align: center;
                transition: all 0.3s ease;
                margin: 20px 0;
                box-sizing: border-box;
            }}
            .file-input:hover {{
                border-color: #4caf50;
                background: rgba(76,175,80,0.1);
            }}
            .btn {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-size: 16px;
                font-weight: 600;
                box-shadow: 0 4px 8px rgba(76,175,80,0.3);
                transition: all 0.3s ease;
                margin-right: 10px;
            }}
            .btn:hover {{
                background: linear-gradient(145deg, #66bb6a, #4caf50);
                transform: translateY(-1px);
            }}
            .btn-secondary {{
                background: linear-gradient(145deg, #757575, #616161);
            }}
            .btn-secondary:hover {{
                background: linear-gradient(145deg, #9e9e9e, #757575);
            }}
            .flash-message {{
                padding: 15px 20px;
                margin: 20px 0;
                border-radius: 12px;
                display: flex;
                align-items: center;
                gap: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                animation: slideIn 0.3s ease;
            }}
            .flash-success {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
                border: 1px solid rgba(255,255,255,0.2);
            }}
            .flash-warning {{
                background: linear-gradient(145deg, #ff9800, #f57c00);
                border: 1px solid rgba(255,255,255,0.2);
            }}
            .flash-error {{
                background: linear-gradient(145deg, #f44336, #d32f2f);
                border: 1px solid rgba(255,255,255,0.2);
            }}
            .flash-icon {{
                font-size: 1.5em;
                flex-shrink: 0;
            }}
            .flash-text {{
                flex: 1;
                font-size: 1em;
                line-height: 1.4;
            }}
            .flash-close {{
                background: rgba(255,255,255,0.2);
                border: none;
                color: white;
                font-size: 24px;
                font-weight: bold;
                cursor: pointer;
                width: 32px;
                height: 32px;
                border-radius: 6px;
                display: flex;
                align-items: center;
                justify-content: center;
                transition: all 0.2s ease;
                flex-shrink: 0;
            }}
            .flash-close:hover {{
                background: rgba(255,255,255,0.3);
                transform: scale(1.1);
            }}
            @keyframes slideIn {{
                from {{
                    transform: translateY(-20px);
                    opacity: 0;
                }}
                to {{
                    transform: translateY(0);
                    opacity: 1;
                }}
            }}
            .info-box {{
                background: rgba(33,150,243,0.2);
                border-left: 4px solid #2196f3;
                padding: 15px;
                margin: 20px 0;
                border-radius: 5px;
            }}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            {render_sidebar_menu('upload')}
            <a href="/settings" class="menu-item placeholder">⚙️ System Settings (Coming Soon)</a>
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
                <h1>📤 Upload Files</h1>
                
                {flash_messages_html}
                
                <div class="info-box">
                    <strong>Upload Limits:</strong><br>
                    • Maximum 5 files per upload<br>
                    • Maximum 3GB per file<br>
                    • Duplicate detection via SHA256 hash<br>
                    • Supported formats: .evtx, .json, .csv, .log, .txt, .xml
                </div>
                
                <div class="upload-container">
                    <form method="POST" enctype="multipart/form-data">
                        <div class="file-input" onclick="document.getElementById('fileInput').click()">
                            <p style="font-size: 3em; margin: 0;">📁</p>
                            <p>Click to select files or drag and drop</p>
                            <p style="font-size: 0.9em; color: rgba(255,255,255,0.7);">Up to 5 files, 3GB each</p>
                        </div>
                        <input type="file" id="fileInput" name="files" multiple style="display: none;" onchange="showSelectedFiles(this)">
                        
                        <div id="selectedFiles" style="margin: 20px 0;"></div>
                        
                        <div style="text-align: center; margin-top: 25px;">
                            <button type="submit" class="btn">Upload Files</button>
                            <button type="button" class="btn btn-secondary" onclick="window.location.href='/files'">Cancel</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <script>
            function showSelectedFiles(input) {{
                const container = document.getElementById('selectedFiles');
                container.innerHTML = '';
                
                if (input.files.length > 0) {{
                    const fileList = document.createElement('div');
                    fileList.style.cssText = 'background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px;';
                    
                    const title = document.createElement('h4');
                    title.textContent = 'Selected Files:';
                    title.style.marginTop = '0';
                    fileList.appendChild(title);
                    
                    for (let i = 0; i < input.files.length; i++) {{
                        const file = input.files[i];
                        const fileInfo = document.createElement('p');
                        fileInfo.textContent = `${{i+1}}. ${{file.name}} (${{(file.size / 1024 / 1024).toFixed(2)}} MB)`;
                        fileInfo.style.margin = '5px 0';
                        fileList.appendChild(fileInfo);
                    }}
                    
                    container.appendChild(fileList);
                }}
            }}
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
    
    file_rows = ""
    for file in files:
        file_size_mb = file.file_size / (1024 * 1024)
        status_class = file.indexing_status.lower().replace(' ', '-')
        
        # Determine status display with progress - will be updated via JavaScript
        if file.indexing_status == 'Uploaded':
            # Check if we're still counting events
            if file.estimated_event_count and file.estimated_event_count > 0:
                status_display = '<div id="status-{0}" class="status-text">Preparing to Index...</div>'.format(file.id)
            else:
                status_display = '<div id="status-{0}" class="status-text">Counting Events...</div>'.format(file.id)
            status_class = 'uploaded'
        elif file.indexing_status == 'Indexing':
            # Show current/total counts without progress bar
            estimated = file.estimated_event_count or int((file.file_size / 1048576) * 1000)
            current_events = file.event_count or 0
            
            status_html = '''<div id="status-{0}" class="status-text" data-file-id="{0}">
                <div style="font-weight: 600; color: #4caf50;">Indexing...</div>
                <div id="events-{0}" style="font-size: 0.9em; color: rgba(255,255,255,0.8); margin-top: 4px;">{1:,} / {2:,} events</div>
            </div>'''.format(file.id, current_events, estimated)
            status_display = status_html
            status_class = 'indexing'
        elif file.indexing_status == 'Running Rules':
            status_html = '''<div id="status-{0}" class="status-text" data-file-id="{0}">
                <div style="font-weight: 600; color: #ff9800;">Running Rules...</div>
            </div>'''.format(file.id)
            status_display = status_html
            status_class = 'running-rules'
        elif file.indexing_status == 'Completed':
            status_display = '<div id="status-{0}" class="status-text">Completed</div>'.format(file.id)
            status_class = 'completed'
        elif file.indexing_status == 'Failed':
            status_display = '<div id="status-{0}" class="status-text">Failed</div>'.format(file.id)
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
        
        # Build action buttons based on user role
        actions_list = []
        actions_list.append(f'<button class="btn-action btn-info" onclick="showFileDetails({file.id})">📋 Details</button>')
        
        # Re-index available for any file (will reset and restart indexing)
        actions_list.append(f'<button class="btn-action btn-reindex" onclick="confirmReindex({file.id})">🔄 Re-index</button>')
        
        # Re-run Rules only available for indexed files
        if file.is_indexed and file.indexing_status in ['Running Rules', 'Completed', 'Failed']:
            actions_list.append(f'<button class="btn-action btn-rules" onclick="confirmRerunRules({file.id})">⚡ Re-run Rules</button>')
        
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
            <td>{actions}</td>
        </tr>
        '''
    
    if not file_rows:
        file_rows = '<tr><td colspan="8" style="text-align: center; padding: 40px;">No files uploaded yet. Click "Upload Files" to add files to this case.</td></tr>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Files - {case.name} - caseScope 7.1</title>
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #1a237e 0%, #3949ab 100%); 
                color: white; 
                margin: 0; 
                display: flex; 
                min-height: 100vh; 
            }}
            .sidebar {{ 
                width: 280px; 
                background: linear-gradient(145deg, #303f9f, #283593); 
                padding: 20px; 
                box-shadow: 
                    5px 0 20px rgba(0,0,0,0.4),
                    inset -1px 0 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
            }}
            .main-content {{ flex: 1; }}
            .header {{ 
                background: linear-gradient(145deg, #283593, #1e88e5); 
                padding: 15px 30px; 
                display: flex; 
                justify-content: space-between; 
                align-items: center;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                border-bottom: 1px solid rgba(255,255,255,0.1);
                min-height: 60px;
            }}
            .case-title {{
                font-size: 1.3em;
                font-weight: 600;
            }}
            .user-info {{ 
                display: flex; 
                align-items: center; 
                gap: 20px;
                font-size: 1em;
                line-height: 1.2;
            }}
            .sidebar-logo {{
                text-align: center;
                font-size: 2.2em;
                font-weight: 300;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                margin-bottom: 15px;
                padding: 5px 0 8px 0;
                border-bottom: 1px solid rgba(76,175,80,0.3);
            }}
            .sidebar-logo .case {{ color: #4caf50; }}
            .sidebar-logo .scope {{ color: white; }}
            .version-badge {{
                font-size: 0.4em;
                background: linear-gradient(145deg, #4caf50, #388e3c);
                color: white;
                padding: 3px 6px;
                border-radius: 6px;
                margin-top: 5px;
                display: inline-block;
                box-shadow: 0 2px 4px rgba(76,175,80,0.3);
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .content {{ padding: 30px; }}
            .menu-item {{ 
                display: block; 
                color: white; 
                text-decoration: none; 
                padding: 12px 16px; 
                margin: 6px 0; 
                border-radius: 12px; 
                background: linear-gradient(145deg, #3949ab, #283593);
                box-shadow: 
                    0 4px 8px rgba(0,0,0,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.1);
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
                font-size: 0.95em;
            }}
            .menu-item:hover {{ 
                background: linear-gradient(145deg, #5c6bc0, #3949ab);
                transform: translateX(5px);
                box-shadow: 
                    0 8px 15px rgba(0,0,0,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.2);
            }}
            .menu-item.active {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
            }}
            .menu-item.placeholder {{ 
                background: linear-gradient(145deg, #424242, #2e2e2e); 
                color: #aaa; 
                cursor: not-allowed;
                opacity: 0.7;
            }}
            .menu-item.placeholder:hover {{
                transform: none;
                box-shadow: 
                    0 4px 8px rgba(0,0,0,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.1);
            }}
            h3.menu-title {{
                font-size: 1.1em;
                margin: 15px 0 8px 0;
                color: #4caf50;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
                border-bottom: 1px solid rgba(76,175,80,0.3);
                padding-bottom: 4px;
            }}
            .logout-btn {{
                background: linear-gradient(145deg, #f44336, #d32f2f);
                color: white !important;
                padding: 8px 16px;
                border-radius: 8px;
                text-decoration: none;
                font-size: 0.9em;
                font-weight: 500;
                box-shadow: 0 4px 8px rgba(244,67,54,0.3);
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .logout-btn:hover {{
                background: linear-gradient(145deg, #ef5350, #f44336);
                box-shadow: 0 6px 12px rgba(244,67,54,0.4);
                transform: translateY(-1px);
                color: white !important;
            }}
            .file-table {{
                width: 100%;
                background: linear-gradient(145deg, #3f51b5, #283593);
                border-radius: 15px;
                overflow: hidden;
                box-shadow: 0 8px 20px rgba(0,0,0,0.3);
                margin-top: 20px;
            }}
            .file-table th, .file-table td {{
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid rgba(255,255,255,0.1);
                vertical-align: middle;
            }}
            .file-table td:last-child {{
                padding: 8px 15px;
            }}
            .file-table th {{
                background: #283593;
                font-weight: 600;
                color: white;
            }}
            .status-uploaded {{ color: #ffb74d; }}
            .status-indexing {{ color: #2196f3; }}
            .status-running-rules {{ color: #9c27b0; }}
            .status-completed {{ color: #4caf50; }}
            .status-failed {{ color: #f44336; }}
            .progress-container {{
                display: flex;
                flex-direction: column;
                gap: 5px;
            }}
            .progress-text {{
                font-size: 0.9em;
                font-weight: 600;
            }}
            .progress-bar-bg {{
                width: 100%;
                height: 20px;
                background: rgba(0,0,0,0.3);
                border-radius: 10px;
                overflow: hidden;
            }}
            .progress-bar {{
                height: 100%;
                border-radius: 10px;
                transition: width 0.5s ease;
            }}
            .indexing-bar {{
                background: linear-gradient(90deg, #2196f3, #42a5f5);
                box-shadow: 0 0 10px rgba(33,150,243,0.5);
            }}
            .rules-bar {{
                background: linear-gradient(90deg, #9c27b0, #ab47bc);
                box-shadow: 0 0 10px rgba(156,39,176,0.5);
            }}
            .progress-events {{
                font-size: 0.85em;
                color: rgba(255,255,255,0.7);
            }}
            .status-text {{
                font-weight: 600;
            }}
            .btn {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-size: 16px;
                font-weight: 600;
                box-shadow: 0 4px 8px rgba(76,175,80,0.3);
                transition: all 0.3s ease;
                text-decoration: none;
                display: inline-block;
            }}
            .btn:hover {{
                background: linear-gradient(145deg, #66bb6a, #4caf50);
                transform: translateY(-1px);
            }}
            .btn-action {{
                color: white;
                padding: 8px 12px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-size: 13px;
                font-weight: 500;
                margin: 2px;
                transition: all 0.2s ease;
                display: inline-block;
                vertical-align: middle;
                white-space: nowrap;
            }}
            .btn-info {{
                background: linear-gradient(145deg, #2196f3, #1976d2);
                box-shadow: 0 2px 4px rgba(33,150,243,0.3);
            }}
            .btn-info:hover {{
                background: linear-gradient(145deg, #42a5f5, #2196f3);
            }}
            .btn-reindex {{
                background: linear-gradient(145deg, #ff9800, #f57c00);
                box-shadow: 0 2px 4px rgba(255,152,0,0.3);
            }}
            .btn-reindex:hover {{
                background: linear-gradient(145deg, #ffa726, #ff9800);
            }}
            .btn-rules {{
                background: linear-gradient(145deg, #9c27b0, #7b1fa2);
                box-shadow: 0 2px 4px rgba(156,39,176,0.3);
            }}
            .btn-rules:hover {{
                background: linear-gradient(145deg, #ab47bc, #9c27b0);
            }}
            .btn-delete {{
                background: linear-gradient(145deg, #f44336, #d32f2f);
                box-shadow: 0 2px 4px rgba(244,67,54,0.3);
            }}
            .btn-delete:hover {{
                background: linear-gradient(145deg, #ef5350, #f44336);
            }}
            .flash-message {{
                padding: 15px 20px;
                margin: 20px 0;
                border-radius: 12px;
                display: flex;
                align-items: center;
                gap: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                animation: slideIn 0.3s ease;
            }}
            .flash-success {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
                border: 1px solid rgba(255,255,255,0.2);
            }}
            .flash-warning {{
                background: linear-gradient(145deg, #ff9800, #f57c00);
                border: 1px solid rgba(255,255,255,0.2);
            }}
            .flash-error {{
                background: linear-gradient(145deg, #f44336, #d32f2f);
                border: 1px solid rgba(255,255,255,0.2);
            }}
            .flash-icon {{
                font-size: 1.5em;
                flex-shrink: 0;
            }}
            .flash-text {{
                flex: 1;
                font-size: 1em;
                line-height: 1.4;
            }}
            .flash-close {{
                background: rgba(255,255,255,0.2);
                border: none;
                color: white;
                font-size: 24px;
                font-weight: bold;
                cursor: pointer;
                width: 32px;
                height: 32px;
                border-radius: 6px;
                display: flex;
                align-items: center;
                justify-content: center;
                transition: all 0.2s ease;
                flex-shrink: 0;
            }}
            .flash-close:hover {{
                background: rgba(255,255,255,0.3);
                transform: scale(1.1);
            }}
            @keyframes slideIn {{
                from {{
                    transform: translateY(-20px);
                    opacity: 0;
                }}
                to {{
                    transform: translateY(0);
                    opacity: 1;
                }}
            }}
        </style>
    </head>
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
                
                <div style="margin: 20px 0; display: flex; gap: 15px; align-items: center;">
                    <a href="/upload" class="btn">📤 Upload Files</a>
                    <button onclick="reindexAllFilesBulk()" class="btn" style="background: linear-gradient(145deg, #2196f3, #1976d2);">🔄 Re-index All Files</button>
                    <button onclick="rerunAllRulesBulk()" class="btn" style="background: linear-gradient(145deg, #ff9800, #f57c00);">⚡ Re-run All Rules</button>
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
                
                // Also check for Uploaded/Pending/Counting/Preparing/Indexing/Running Rules status
                const statusElements = document.querySelectorAll('[id^="status-"]');
                statusElements.forEach(function(elem) {{
                    const fileId = elem.id.split('-')[1];
                    const statusText = elem.textContent;
                    if ((statusText.includes('Uploaded') || 
                         statusText.includes('Pending') || 
                         statusText.includes('Counting') || 
                         statusText.includes('Preparing') ||
                         statusText.includes('Indexing') ||
                         statusText.includes('Running Rules')) && 
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
                
                // Auto-refresh page every 5 seconds if there are active files
                // This ensures status changes are reflected (Uploaded -> Indexing, etc.)
                if (activeFiles.length > 0) {{
                    setInterval(function() {{
                        console.log('Auto-refreshing page to update file statuses...');
                        window.location.reload();
                    }}, 5000); // Refresh every 5 seconds
                }}
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
                            
                            if (data.status === 'Indexing') {{
                                // Update count text (no progress bar)
                                if (eventsText) {{
                                    const currentEvents = data.event_count.toLocaleString();
                                    const totalEvents = data.estimated_event_count.toLocaleString();
                                    eventsText.textContent = currentEvents + ' / ' + totalEvents + ' events';
                                }}
                            }} else if (data.status === 'Running Rules') {{
                                // No progress bar needed, just status text
                            }} else if (data.status === 'Completed') {{
                                // Reload page to show final status
                                console.log('File completed, reloading page...');
                                window.location.reload();
                            }} else if (data.status === 'Failed') {{
                                // Reload page to show failure
                                console.log('File failed, reloading page...');
                                window.location.reload();
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
        </script>
    </body>
    </html>
    '''

def render_search_page(case, query_str, results, total_hits, page, per_page, error_message, indexed_file_count, violations_only=False):
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
            
            result_rows += f'''
            <tr class="result-row" onclick="toggleDetails('{result_id}')">
                <td>{result['event_id']}</td>
                <td>{result['timestamp'][:19] if result['timestamp'] != 'N/A' else 'N/A'}</td>
                <td>{escaped_event_type}</td>
                <td><span class="field-tag" onclick="addToQuery(event, 'source_filename', '{escaped_source_file}')">{escaped_source_file}</span></td>
                <td><span class="field-tag" onclick="addToQuery(event, 'Computer', '{escaped_computer}')">{escaped_computer}</span></td>
            </tr>
            <tr id="{result_id}" class="details-row" style="display: none;">
                <td colspan="5">
                    <div class="event-details">
                        <h4>Full Event Data</h4>
                        <pre>{json.dumps(result['full_data'], indent=2)}</pre>
                    </div>
                </td>
            </tr>
            '''
    elif query_str and not error_message:
        result_rows = '<tr><td colspan="5" style="text-align: center; padding: 40px; color: #aaa;">No results found for your query.</td></tr>'
    elif not query_str:
        result_rows = '<tr><td colspan="5" style="text-align: center; padding: 40px; color: #aaa;">Enter a search query above to search indexed events.</td></tr>'
    
    if error_message:
        result_rows = f'<tr><td colspan="5" style="text-align: center; padding: 40px; color: #f44336;"><strong>Error:</strong> {error_message}</td></tr>'
    
    # Pagination
    total_pages = (total_hits + per_page - 1) // per_page if total_hits > 0 else 1
    pagination_html = ""
    if total_hits > per_page:
        pagination_html = '<div class="pagination">'
        if page > 1:
            pagination_html += f'<button class="page-btn" onclick="searchPage({page - 1})">← Previous</button>'
        pagination_html += f'<span class="page-info">Page {page} of {total_pages} ({total_hits:,} results)</span>'
        if page < total_pages:
            pagination_html += f'<button class="page-btn" onclick="searchPage({page + 1})">Next →</button>'
        pagination_html += '</div>'
    elif total_hits > 0:
        pagination_html = f'<div class="pagination"><span class="page-info">{total_hits:,} result{"s" if total_hits != 1 else ""} found</span></div>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search Events - {case.name} - caseScope 7.1</title>
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #1a237e 0%, #3949ab 100%); 
                color: white; 
                margin: 0; 
                display: flex; 
                min-height: 100vh; 
            }}
            .sidebar {{ 
                width: 280px; 
                background: linear-gradient(145deg, #303f9f, #283593); 
                padding: 20px; 
                box-shadow: 
                    5px 0 20px rgba(0,0,0,0.4),
                    inset -1px 0 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
            }}
            .main-content {{ flex: 1; }}
            .header {{ 
                background: linear-gradient(145deg, #283593, #1e88e5); 
                padding: 15px 30px; 
                display: flex; 
                justify-content: space-between; 
                align-items: center;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                border-bottom: 1px solid rgba(255,255,255,0.1);
                min-height: 60px;
            }}
            .case-title {{
                font-size: 1.3em;
                font-weight: 600;
            }}
            .user-info {{ 
                display: flex; 
                align-items: center; 
                gap: 20px;
                font-size: 1em;
                line-height: 1.2;
            }}
            .sidebar-logo {{
                text-align: center;
                font-size: 2.2em;
                font-weight: 300;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                margin-bottom: 15px;
                padding: 5px 0 8px 0;
                border-bottom: 1px solid rgba(76,175,80,0.3);
            }}
            .sidebar-logo .case {{ color: #4caf50; }}
            .sidebar-logo .scope {{ color: white; }}
            .version-badge {{
                font-size: 0.4em;
                background: linear-gradient(145deg, #4caf50, #388e3c);
                color: white;
                padding: 3px 6px;
                border-radius: 6px;
                margin-top: 5px;
                display: inline-block;
                box-shadow: 0 2px 4px rgba(76,175,80,0.3);
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .content {{ padding: 30px; }}
            .menu-item {{ 
                display: block; 
                color: white; 
                text-decoration: none; 
                padding: 12px 16px; 
                margin: 6px 0; 
                border-radius: 12px; 
                background: linear-gradient(145deg, #3949ab, #283593);
                box-shadow: 
                    0 4px 8px rgba(0,0,0,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.1);
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
                font-size: 0.95em;
            }}
            .menu-item:hover {{ 
                background: linear-gradient(145deg, #5c6bc0, #3949ab);
                transform: translateX(5px);
                box-shadow: 
                    0 8px 15px rgba(0,0,0,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.2);
            }}
            .menu-item.active {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
            }}
            .menu-item.placeholder {{ 
                background: linear-gradient(145deg, #424242, #2e2e2e); 
                color: #aaa; 
                cursor: not-allowed;
                opacity: 0.7;
            }}
            .menu-title {{
                font-size: 0.9em;
                color: rgba(255,255,255,0.7);
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin: 20px 0 10px 0;
                padding-left: 5px;
            }}
            .logout-btn {{
                background: linear-gradient(145deg, #f44336, #d32f2f);
                color: white;
                padding: 8px 20px;
                border-radius: 8px;
                text-decoration: none;
                box-shadow: 0 2px 8px rgba(244,67,54,0.3);
                border: 1px solid rgba(255,255,255,0.1);
                transition: all 0.3s ease;
                display: inline-block;
            }}
            .logout-btn:hover {{
                background: linear-gradient(145deg, #ef5350, #f44336);
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(244,67,54,0.4);
            }}
            .flash-message {{
                padding: 15px 20px;
                margin: 20px 0;
                border-radius: 12px;
                display: flex;
                align-items: center;
                gap: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                animation: slideIn 0.3s ease;
            }}
            .flash-success {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
                border: 1px solid rgba(255,255,255,0.2);
            }}
            .flash-warning {{
                background: linear-gradient(145deg, #ff9800, #f57c00);
                border: 1px solid rgba(255,255,255,0.2);
            }}
            .flash-error {{
                background: linear-gradient(145deg, #f44336, #d32f2f);
                border: 1px solid rgba(255,255,255,0.2);
            }}
            .flash-icon {{
                font-size: 1.5em;
                flex-shrink: 0;
            }}
            .flash-text {{
                flex: 1;
                font-size: 1em;
                line-height: 1.4;
            }}
            .flash-close {{
                background: rgba(255,255,255,0.2);
                border: none;
                color: white;
                font-size: 24px;
                font-weight: bold;
                cursor: pointer;
                width: 32px;
                height: 32px;
                border-radius: 6px;
                display: flex;
                align-items: center;
                justify-content: center;
                transition: all 0.2s ease;
                flex-shrink: 0;
            }}
            .flash-close:hover {{
                background: rgba(255,255,255,0.3);
                transform: scale(1.1);
            }}
            @keyframes slideIn {{
                from {{
                    transform: translateY(-20px);
                    opacity: 0;
                }}
                to {{
                    transform: translateY(0);
                    opacity: 1;
                }}
            }}
            .search-box {{
                background: linear-gradient(145deg, #3f51b5, #283593);
                padding: 25px;
                border-radius: 16px;
                margin-bottom: 30px;
                box-shadow: 
                    0 8px 24px rgba(0,0,0,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.1);
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .search-input {{
                width: 100%;
                padding: 15px 20px;
                font-size: 1.1em;
                border: 2px solid rgba(255,255,255,0.2);
                border-radius: 12px;
                background: rgba(255,255,255,0.1);
                color: white;
                box-sizing: border-box;
                margin-bottom: 15px;
            }}
            .search-input:focus {{
                outline: none;
                border-color: #4caf50;
                background: rgba(255,255,255,0.15);
            }}
            .search-input::placeholder {{
                color: rgba(255,255,255,0.5);
            }}
            .search-actions {{
                display: flex;
                gap: 15px;
                align-items: center;
            }}
            .btn-search {{
                padding: 12px 30px;
                background: linear-gradient(145deg, #4caf50, #388e3c);
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 1em;
                font-weight: 600;
                cursor: pointer;
                box-shadow: 0 4px 12px rgba(76,175,80,0.4);
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .btn-search:hover {{
                background: linear-gradient(145deg, #66bb6a, #4caf50);
                transform: translateY(-2px);
                box-shadow: 0 6px 16px rgba(76,175,80,0.5);
            }}
            .help-toggle {{
                background: rgba(33,150,243,0.3);
                color: white;
                padding: 10px 20px;
                border: 1px solid rgba(33,150,243,0.5);
                border-radius: 8px;
                cursor: pointer;
                font-size: 0.95em;
                transition: all 0.3s ease;
            }}
            .help-toggle:hover {{
                background: rgba(33,150,243,0.5);
            }}
            .help-box {{
                background: rgba(33,150,243,0.15);
                border-left: 4px solid #2196f3;
                padding: 20px;
                margin-top: 15px;
                border-radius: 8px;
                display: none;
            }}
            .help-box h4 {{
                margin: 0 0 15px 0;
                color: #64b5f6;
            }}
            .help-box ul {{
                margin: 10px 0;
                padding-left: 20px;
            }}
            .help-box li {{
                margin: 8px 0;
                line-height: 1.6;
            }}
            .help-box code {{
                background: rgba(0,0,0,0.3);
                padding: 2px 8px;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                color: #4caf50;
            }}
            .results-table {{
                width: 100%;
                border-collapse: collapse;
                background: linear-gradient(145deg, #3f51b5, #283593);
                border-radius: 16px;
                overflow: hidden;
                box-shadow: 0 8px 24px rgba(0,0,0,0.4);
            }}
            .results-table thead {{
                background: #283593;
            }}
            .results-table th {{
                padding: 15px;
                text-align: left;
                font-weight: 600;
                border-bottom: 2px solid rgba(255,255,255,0.1);
            }}
            .result-row {{
                cursor: pointer;
                transition: all 0.2s ease;
                border-bottom: 1px solid rgba(255,255,255,0.05);
            }}
            .result-row:hover {{
                background: rgba(255,255,255,0.1);
            }}
            .result-row td {{
                padding: 12px 15px;
                vertical-align: middle;
            }}
            .details-row td {{
                padding: 0;
                background: rgba(0,0,0,0.3);
            }}
            .event-details {{
                padding: 20px;
                max-height: 500px;
                overflow-y: auto;
            }}
            .event-details h4 {{
                margin: 0 0 15px 0;
                color: #4caf50;
            }}
            .event-details pre {{
                background: rgba(0,0,0,0.5);
                padding: 15px;
                border-radius: 8px;
                overflow-x: auto;
                font-size: 0.9em;
                line-height: 1.5;
                color: #e0e0e0;
            }}
            .field-tag {{
                background: rgba(76,175,80,0.3);
                padding: 4px 10px;
                border-radius: 6px;
                font-size: 0.9em;
                border: 1px solid rgba(76,175,80,0.5);
                cursor: pointer;
                transition: all 0.2s ease;
                display: inline-block;
            }}
            .field-tag:hover {{
                background: rgba(76,175,80,0.5);
                transform: scale(1.05);
            }}
            .pagination {{
                margin: 30px 0;
                display: flex;
                gap: 15px;
                align-items: center;
                justify-content: center;
            }}
            .page-btn {{
                padding: 10px 20px;
                background: linear-gradient(145deg, #3949ab, #283593);
                color: white;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-weight: 600;
                box-shadow: 0 4px 8px rgba(0,0,0,0.3);
                transition: all 0.3s ease;
            }}
            .page-btn:hover {{
                background: linear-gradient(145deg, #5c6bc0, #3949ab);
                transform: translateY(-2px);
            }}
            .page-info {{
                color: rgba(255,255,255,0.8);
                font-size: 0.95em;
            }}
            .stats-bar {{
                background: rgba(33,150,243,0.2);
                padding: 12px 20px;
                border-radius: 10px;
                margin-bottom: 20px;
                border-left: 4px solid #2196f3;
            }}
        </style>
    </head>
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
                
                <div class="search-box">
                    <form method="POST" id="searchForm">
                        <input type="text" name="query" class="search-input" placeholder="Enter search query (e.g., EventID:4624 AND Computer:SERVER01)" value="{query_str}" autofocus>
                        <input type="hidden" name="page" id="pageInput" value="{page}">
                        <div class="search-actions">
                            <label style="display: flex; align-items: center; margin-right: 15px; color: rgba(255,255,255,0.9);">
                                <input type="checkbox" name="violations_only" value="true" {'checked' if violations_only else ''} style="margin-right: 8px; width: 18px; height: 18px; cursor: pointer;">
                                <span style="font-size: 14px;">🚨 Show only SIGMA violations</span>
                            </label>
                            <button type="submit" class="btn-search">🔍 Search</button>
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
                            <th>Timestamp</th>
                            <th>Event Type</th>
                            <th>Source File</th>
                            <th>Computer</th>
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
            
            function searchPage(pageNum) {{
                document.getElementById('pageInput').value = pageNum;
                document.getElementById('searchForm').submit();
            }}
        </script>
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
        rule_violations = SigmaViolation.query.filter_by(rule_id=rule.id).count()
        
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
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #1a237e 0%, #3949ab 100%); 
                color: white; 
                margin: 0; 
                display: flex; 
                min-height: 100vh; 
            }}
            .sidebar {{ 
                width: 280px; 
                background: linear-gradient(145deg, #303f9f, #283593); 
                padding: 20px; 
                box-shadow: 5px 0 20px rgba(0,0,0,0.4), inset -1px 0 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
            }}
            .main-content {{ flex: 1; }}
            .header {{ 
                background: linear-gradient(145deg, #283593, #1e88e5); 
                padding: 15px 30px; 
                display: flex; 
                justify-content: space-between; 
                align-items: center;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                border-bottom: 1px solid rgba(255,255,255,0.1);
                min-height: 60px;
            }}
            .case-title {{ font-size: 1.3em; font-weight: 600; }}
            .user-info {{ display: flex; align-items: center; gap: 20px; font-size: 1em; line-height: 1.2; }}
            .sidebar-logo {{
                text-align: center; font-size: 2.2em; font-weight: 300; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                margin-bottom: 15px; padding: 5px 0 8px 0; border-bottom: 1px solid rgba(76,175,80,0.3);
            }}
            .sidebar-logo .case {{ color: #4caf50; }}
            .sidebar-logo .scope {{ color: white; }}
            .version-badge {{
                font-size: 0.4em; background: linear-gradient(145deg, #4caf50, #388e3c); color: white;
                padding: 3px 6px; border-radius: 6px; margin-top: 5px; display: inline-block;
                box-shadow: 0 2px 4px rgba(76,175,80,0.3); border: 1px solid rgba(255,255,255,0.1);
            }}
            .content {{ padding: 30px; }}
            .menu-title {{
                font-size: 0.8em; font-weight: 600; color: rgba(255,255,255,0.6); text-transform: uppercase;
                letter-spacing: 0.5px; margin: 15px 0 8px 0; padding-left: 5px;
            }}
            .menu-item {{ 
                display: block; color: white; text-decoration: none; padding: 12px 16px; margin: 6px 0; 
                border-radius: 12px; background: linear-gradient(145deg, #3949ab, #283593);
                box-shadow: 0 4px 8px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.1);
                transition: all 0.3s ease; border: 1px solid rgba(255,255,255,0.1); font-size: 0.95em;
            }}
            .menu-item:hover {{ 
                background: linear-gradient(145deg, #5c6bc0, #3949ab);
                transform: translateX(5px);
                box-shadow: 0 8px 15px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.2);
            }}
            .menu-item.active {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
                box-shadow: 0 4px 12px rgba(76,175,80,0.4), inset 0 1px 0 rgba(255,255,255,0.2);
            }}
            .menu-item.placeholder {{ 
                background: linear-gradient(145deg, #424242, #2e2e2e); 
                color: #aaa; cursor: not-allowed; opacity: 0.7;
            }}
            .menu-item.placeholder:hover {{
                transform: none;
                box-shadow: 0 4px 8px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.1);
            }}
            .logout-btn {{
                background: linear-gradient(145deg, #f44336, #d32f2f); color: white !important;
                padding: 8px 16px; border-radius: 8px; text-decoration: none; font-size: 0.9em;
                font-weight: 500; box-shadow: 0 4px 8px rgba(244,67,54,0.3); transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .logout-btn:hover {{
                background: linear-gradient(145deg, #ef5350, #f44336);
                box-shadow: 0 6px 12px rgba(244,67,54,0.4); transform: translateY(-1px);
            }}
            .flash-message {{
                padding: 15px 20px; margin: 20px 0; border-radius: 12px; display: flex; align-items: center;
                gap: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); animation: slideIn 0.3s ease;
            }}
            .flash-success {{ background: linear-gradient(145deg, #4caf50, #388e3c); border: 1px solid rgba(255,255,255,0.2); }}
            .flash-warning {{ background: linear-gradient(145deg, #ff9800, #f57c00); border: 1px solid rgba(255,255,255,0.2); }}
            .flash-error {{ background: linear-gradient(145deg, #f44336, #d32f2f); border: 1px solid rgba(255,255,255,0.2); }}
            .flash-icon {{ font-size: 1.5em; flex-shrink: 0; }}
            .flash-text {{ flex: 1; font-size: 1em; line-height: 1.4; }}
            .flash-close {{
                background: rgba(255,255,255,0.2); border: none; color: white; font-size: 24px; font-weight: bold;
                cursor: pointer; width: 32px; height: 32px; border-radius: 6px; display: flex; align-items: center;
                justify-content: center; transition: all 0.2s ease; flex-shrink: 0;
            }}
            .flash-close:hover {{ background: rgba(255,255,255,0.3); transform: scale(1.1); }}
            @keyframes slideIn {{ from {{ transform: translateY(-20px); opacity: 0; }} to {{ transform: translateY(0); opacity: 1; }} }}
            .stats-bar {{
                background: linear-gradient(145deg, #3f51b5, #283593); padding: 20px; border-radius: 12px;
                margin-bottom: 25px; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            }}
            .stat-item {{
                text-align: center; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 8px;
            }}
            .stat-value {{ font-size: 2em; font-weight: bold; color: #4caf50; }}
            .stat-label {{ font-size: 0.9em; color: rgba(255,255,255,0.7); margin-top: 5px; }}
            .upload-box {{
                background: linear-gradient(145deg, #3f51b5, #283593); padding: 25px; border-radius: 12px;
                margin-bottom: 25px; box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            }}
            .upload-box h3 {{ margin-top: 0; }}
            .upload-box input[type="file"] {{
                display: block; margin: 15px 0; padding: 10px; background: rgba(255,255,255,0.1);
                border: 2px dashed rgba(255,255,255,0.3); border-radius: 8px; color: white; width: 100%;
                box-sizing: border-box;
            }}
            .upload-box button {{
                padding: 12px 24px; background: linear-gradient(145deg, #4caf50, #388e3c); color: white;
                border: none; border-radius: 8px; font-size: 1em; cursor: pointer; box-shadow: 0 4px 8px rgba(76,175,80,0.3);
            }}
            .upload-box button:hover {{ background: linear-gradient(145deg, #66bb6a, #4caf50); }}
            .rules-table {{
                width: 100%; border-collapse: collapse; background: linear-gradient(145deg, #3f51b5, #283593);
                border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            }}
            .rules-table thead {{ background: #283593; }}
            .rules-table th {{
                padding: 15px; text-align: left; font-weight: 600; border-bottom: 2px solid rgba(255,255,255,0.1);
            }}
            .rule-row {{ cursor: pointer; transition: all 0.2s ease; border-bottom: 1px solid rgba(255,255,255,0.05); }}
            .rule-row:hover {{ background: rgba(255,255,255,0.1); }}
            .rule-row td {{ padding: 15px; vertical-align: top; }}
            .rule-title {{ font-weight: 600; margin-bottom: 5px; }}
            .rule-meta {{ font-size: 0.85em; color: rgba(255,255,255,0.7); }}
            .level-badge {{
                padding: 4px 10px; border-radius: 6px; font-size: 0.85em; font-weight: 600; color: white;
                box-shadow: 0 2px 4px rgba(0,0,0,0.3); display: inline-block;
            }}
            .status-badge {{
                padding: 4px 10px; border-radius: 6px; font-size: 0.85em; font-weight: 600;
                display: inline-block;
            }}
            .status-enabled {{ background: linear-gradient(145deg, #4caf50, #388e3c); color: white; }}
            .status-disabled {{ background: linear-gradient(145deg, #757575, #616161); color: white; }}
            .tag {{
                background: rgba(33,150,243,0.3); padding: 2px 8px; border-radius: 4px; font-size: 0.8em;
                margin-right: 5px; border: 1px solid rgba(33,150,243,0.5);
            }}
            .builtin-badge {{
                background: linear-gradient(145deg, #9c27b0, #7b1fa2); padding: 3px 8px; border-radius: 4px;
                font-size: 0.8em; margin-right: 5px; border: 1px solid rgba(255,255,255,0.2);
            }}
            .user-badge {{
                background: linear-gradient(145deg, #00bcd4, #0097a7); padding: 3px 8px; border-radius: 4px;
                font-size: 0.8em; margin-right: 5px; border: 1px solid rgba(255,255,255,0.2);
            }}
            .actions-cell {{ white-space: nowrap; }}
            .btn-action {{
                padding: 6px 10px; margin: 0 2px; border: none; border-radius: 6px; cursor: pointer;
                font-size: 1em; transition: all 0.2s ease; background: rgba(255,255,255,0.1);
            }}
            .btn-action:hover {{ background: rgba(255,255,255,0.2); transform: scale(1.1); }}
            .btn-toggle {{ background: linear-gradient(145deg, #ff9800, #f57c00); color: white; }}
            .btn-view {{ background: linear-gradient(145deg, #2196f3, #1976d2); color: white; }}
            .btn-delete {{ background: linear-gradient(145deg, #f44336, #d32f2f); color: white; }}
            .rule-details td {{ padding: 20px !important; background: rgba(0,0,0,0.3); }}
            .rule-yaml {{ background: rgba(0,0,0,0.5); padding: 15px; border-radius: 8px; }}
            .rule-yaml h4 {{ margin: 0 0 10px 0; color: #4caf50; }}
            .rule-yaml pre {{
                background: rgba(0,0,0,0.5); padding: 15px; border-radius: 8px; overflow-x: auto;
                font-size: 0.9em; line-height: 1.5; color: #e0e0e0; margin: 0;
            }}
        </style>
    </head>
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
        </tr>
        <tr id="violation-details-{v.id}" class="violation-details" style="display: none;">
            <td colspan="8">
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
                    <h4>Event Data</h4>
                    <pre class="event-json">{json.dumps(event_data, indent=2)}</pre>
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
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #1a237e 0%, #3949ab 100%); 
                color: white; 
                margin: 0; 
                display: flex; 
                min-height: 100vh; 
            }}
            .sidebar {{ 
                width: 280px; 
                background: linear-gradient(145deg, #303f9f, #283593); 
                padding: 20px; 
                box-shadow: 5px 0 20px rgba(0,0,0,0.4), inset -1px 0 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
            }}
            .main-content {{ flex: 1; }}
            .header {{ 
                background: linear-gradient(145deg, #283593, #1e88e5); 
                padding: 15px 30px; 
                display: flex; 
                justify-content: space-between; 
                align-items: center;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                border-bottom: 1px solid rgba(255,255,255,0.1);
                min-height: 60px;
            }}
            .case-title {{ font-size: 1.3em; font-weight: 600; }}
            .user-info {{ display: flex; align-items: center; gap: 20px; font-size: 1em; line-height: 1.2; }}
            .sidebar-logo {{
                text-align: center; font-size: 2.2em; font-weight: 300; text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                margin-bottom: 15px; padding: 5px 0 8px 0; border-bottom: 1px solid rgba(76,175,80,0.3);
            }}
            .sidebar-logo .case {{ color: #4caf50; }}
            .sidebar-logo .scope {{ color: white; }}
            .version-badge {{
                font-size: 0.4em; background: linear-gradient(145deg, #4caf50, #388e3c); color: white;
                padding: 3px 6px; border-radius: 6px; margin-top: 5px; display: inline-block;
                box-shadow: 0 2px 4px rgba(76,175,80,0.3); border: 1px solid rgba(255,255,255,0.1);
            }}
            .content {{ padding: 30px; }}
            .menu-title {{
                font-size: 0.8em; font-weight: 600; color: rgba(255,255,255,0.6); text-transform: uppercase;
                letter-spacing: 0.5px; margin: 15px 0 8px 0; padding-left: 5px;
            }}
            .menu-item {{ 
                display: block; color: white; text-decoration: none; padding: 12px 16px; margin: 6px 0; 
                border-radius: 12px; background: linear-gradient(145deg, #3949ab, #283593);
                box-shadow: 0 4px 8px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.1);
                transition: all 0.3s ease; border: 1px solid rgba(255,255,255,0.1); font-size: 0.95em;
            }}
            .menu-item:hover {{ 
                background: linear-gradient(145deg, #5c6bc0, #3949ab);
                transform: translateX(5px);
                box-shadow: 0 8px 15px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.2);
            }}
            .menu-item.active {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
                box-shadow: 0 4px 12px rgba(76,175,80,0.4), inset 0 1px 0 rgba(255,255,255,0.2);
            }}
            .menu-item.placeholder {{ 
                background: linear-gradient(145deg, #424242, #2e2e2e); 
                color: #aaa; cursor: not-allowed; opacity: 0.7;
            }}
            .menu-item.placeholder:hover {{
                transform: none;
                box-shadow: 0 4px 8px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.1);
            }}
            .logout-btn {{
                background: linear-gradient(145deg, #f44336, #d32f2f); color: white !important;
                padding: 8px 16px; border-radius: 8px; text-decoration: none; font-size: 0.9em;
                font-weight: 500; box-shadow: 0 4px 8px rgba(244,67,54,0.3); transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .logout-btn:hover {{
                background: linear-gradient(145deg, #ef5350, #f44336);
                box-shadow: 0 6px 12px rgba(244,67,54,0.4); transform: translateY(-1px);
            }}
            .stats-bar {{
                background: linear-gradient(145deg, #3f51b5, #283593); padding: 20px; border-radius: 12px;
                margin-bottom: 25px; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 15px; box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            }}
            .stat-item {{
                text-align: center; padding: 12px; background: rgba(255,255,255,0.05); border-radius: 8px;
            }}
            .stat-value {{ font-size: 1.8em; font-weight: bold; }}
            .stat-value.critical {{ color: #f44336; }}
            .stat-value.high {{ color: #ff5722; }}
            .stat-value.medium {{ color: #ff9800; }}
            .stat-value.low {{ color: #2196f3; }}
            .stat-label {{ font-size: 0.85em; color: rgba(255,255,255,0.7); margin-top: 5px; }}
            .filter-bar {{
                background: linear-gradient(145deg, #3f51b5, #283593); padding: 20px; border-radius: 12px;
                margin-bottom: 25px; display: flex; gap: 15px; align-items: center; flex-wrap: wrap;
            }}
            .filter-bar select {{
                padding: 10px; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.3);
                border-radius: 8px; color: white; font-size: 1em;
            }}
            .filter-bar select option {{ background: #283593; }}
            .violations-table {{
                width: 100%; border-collapse: collapse; background: linear-gradient(145deg, #3f51b5, #283593);
                border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            }}
            .violations-table thead {{ background: #283593; }}
            .violations-table th {{
                padding: 15px; text-align: left; font-weight: 600; border-bottom: 2px solid rgba(255,255,255,0.1);
                font-size: 0.9em;
            }}
            .violation-row {{ cursor: pointer; transition: all 0.2s ease; border-bottom: 1px solid rgba(255,255,255,0.05); }}
            .violation-row:hover {{ background: rgba(255,255,255,0.1); }}
            .violation-row td {{ padding: 12px; vertical-align: middle; font-size: 0.9em; }}
            .severity-badge {{
                padding: 4px 10px; border-radius: 6px; font-size: 0.85em; font-weight: 600; color: white;
                box-shadow: 0 2px 4px rgba(0,0,0,0.3); display: inline-block;
            }}
            .review-badge {{
                padding: 4px 10px; border-radius: 6px; font-size: 0.85em; font-weight: 600;
                display: inline-block;
            }}
            .review-reviewed {{ background: linear-gradient(145deg, #4caf50, #388e3c); color: white; }}
            .review-pending {{ background: linear-gradient(145deg, #ff9800, #f57c00); color: white; }}
            .actions-cell {{ white-space: nowrap; }}
            .btn-action {{
                padding: 6px 10px; margin: 0 2px; border: none; border-radius: 6px; cursor: pointer;
                font-size: 1em; transition: all 0.2s ease; background: rgba(255,255,255,0.1);
            }}
            .btn-action:hover {{ background: rgba(255,255,255,0.2); transform: scale(1.1); }}
            .btn-view {{ background: linear-gradient(145deg, #2196f3, #1976d2); color: white; }}
            .btn-review {{ background: linear-gradient(145deg, #4caf50, #388e3c); color: white; }}
            .violation-details td {{ padding: 20px !important; background: rgba(0,0,0,0.3); }}
            .violation-detail-panel {{ background: rgba(0,0,0,0.5); padding: 20px; border-radius: 8px; }}
            .detail-grid {{
                display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px; margin-bottom: 20px;
            }}
            .detail-item strong {{ color: #4caf50; display: block; margin-bottom: 5px; }}
            .event-json {{
                background: rgba(0,0,0,0.5); padding: 15px; border-radius: 8px; overflow-x: auto;
                font-size: 0.85em; line-height: 1.5; color: #e0e0e0; margin: 0;
            }}
            .pagination {{
                margin: 30px 0; display: flex; gap: 15px; align-items: center; justify-content: center;
            }}
            .page-btn {{
                padding: 10px 20px; background: linear-gradient(145deg, #3949ab, #283593);
                color: white; text-decoration: none; border-radius: 8px; transition: all 0.3s ease;
            }}
            .page-btn:hover {{ background: linear-gradient(145deg, #5c6bc0, #3949ab); }}
        </style>
    </head>
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
                        </tr>
                    </thead>
                    <tbody>
                        {violations_html if violations_html else '<tr><td colspan="8" style="text-align: center; padding: 40px; color: #aaa;">No violations found with current filters.</td></tr>'}
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
        </script>
    </body>
    </html>
    '''

def render_case_form():
    """Render case creation form with sidebar layout"""
    sidebar_menu = render_sidebar_menu('case_select')
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Create New Case - caseScope 7.1</title>
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #1a237e 0%, #3949ab 100%); 
                color: white; 
                margin: 0; 
                display: flex;
                min-height: 100vh; 
            }}
            .sidebar {{ 
                width: 280px; 
                background: linear-gradient(145deg, #303f9f, #283593); 
                padding: 20px; 
                box-shadow: 
                    5px 0 20px rgba(0,0,0,0.4),
                    inset -1px 0 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
            }}
            .main-content {{ flex: 1; display: flex; align-items: center; justify-content: center; }}
            .sidebar-logo {{
                text-align: center;
                font-size: 2.2em;
                font-weight: bold;
                margin-bottom: 5px;
                padding: 5px;
            }}
            .version-badge {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
                color: white;
                padding: 4px 12px;
                border-radius: 12px;
                font-size: 0.75em;
                display: inline-block;
                box-shadow: 0 2px 8px rgba(0,0,0,0.3);
                margin-top: 5px;
            }}
            .menu-title {{
                color: rgba(255,255,255,0.6);
                font-size: 0.85em;
                font-weight: 600;
                text-transform: uppercase;
                margin: 15px 0 8px 0;
                letter-spacing: 1px;
            }}
            .menu-item {{
                display: block;
                padding: 10px 15px;
                margin: 4px 0;
                background: rgba(255,255,255,0.05);
                border-radius: 8px;
                color: white;
                text-decoration: none;
                transition: all 0.3s;
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .menu-item:hover {{
                background: rgba(255,255,255,0.15);
                transform: translateX(5px);
                box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            }}
            .menu-item.active {{
                background: linear-gradient(145deg, #1e88e5, #1976d2);
                border-color: rgba(255,255,255,0.2);
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            }}
            .menu-item.placeholder {{
                opacity: 0.5;
                cursor: not-allowed;
            }}
            .form-container {{ 
                max-width: 600px; 
                width: 90%; 
                background: linear-gradient(145deg, #283593, #1e88e5); 
                padding: 30px; 
                border-radius: 20px; 
                box-shadow: 
                    0 20px 40px rgba(0,0,0,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .form-group {{ margin-bottom: 18px; }}
            label {{ display: block; margin-bottom: 5px; color: rgba(255,255,255,0.9); font-weight: 500; }}
            input, textarea, select {{ 
                width: 100%; 
                padding: 12px 16px; 
                border: none; 
                border-radius: 8px; 
                background: rgba(255,255,255,0.1);
                color: white;
                font-size: 14px;
                box-shadow: inset 0 2px 5px rgba(0,0,0,0.2);
                border: 1px solid rgba(255,255,255,0.1);
                box-sizing: border-box;
            }}
            textarea {{ resize: vertical; min-height: 80px; }}
            button {{ 
                background: linear-gradient(145deg, #4caf50, #388e3c); 
                color: white; 
                padding: 12px 24px; 
                border: none; 
                border-radius: 8px; 
                cursor: pointer; 
                font-size: 16px;
                font-weight: 600;
                box-shadow: 0 4px 8px rgba(76,175,80,0.3);
                transition: all 0.3s ease;
                margin-right: 10px;
            }}
            button:hover {{ 
                background: linear-gradient(145deg, #66bb6a, #4caf50);
                transform: translateY(-1px);
            }}
            .cancel-btn {{
                background: linear-gradient(145deg, #757575, #616161);
            }}
            .cancel-btn:hover {{
                background: linear-gradient(145deg, #9e9e9e, #757575);
            }}
            h2 {{ text-align: center; margin-bottom: 25px; font-weight: 300; }}
        </style>
    </head>
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
                    <label for="priority">Priority</label>
                    <select id="priority" name="priority">
                        <option value="Low">Low</option>
                        <option value="Medium" selected>Medium</option>
                        <option value="High">High</option>
                        <option value="Critical">Critical</option>
                    </select>
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
        case_rows += f'''
        <tr class="case-row {active_class}" onclick="selectCase({case.id})">
            <td>{case.case_number}</td>
            <td>{case.name}</td>
            <td><span class="priority-{case.priority.lower()}">{case.priority}</span></td>
            <td><span class="status-{case.status.lower().replace(' ', '-')}">{case.status}</span></td>
            <td>{case.file_count}</td>
            <td>{case.created_at.strftime('%Y-%m-%d')}</td>
            <td>{case.creator.username}</td>
            <td>{'✓ Active' if case.id == active_case_id else ''}</td>
        </tr>
        '''
    
    # Use the main dashboard layout but with case selection content
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Case Selection - caseScope 7.1</title>
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #1a237e 0%, #3949ab 100%); 
                color: white; 
                margin: 0; 
                display: flex; 
                min-height: 100vh; 
            }}
            .sidebar {{ 
                width: 280px; 
                background: linear-gradient(145deg, #303f9f, #283593); 
                padding: 20px; 
                box-shadow: 
                    5px 0 20px rgba(0,0,0,0.4),
                    inset -1px 0 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
            }}
            .main-content {{ flex: 1; }}
            .header {{ 
                background: linear-gradient(145deg, #283593, #1e88e5); 
                padding: 15px 30px; 
                display: flex; 
                justify-content: flex-end; 
                align-items: center;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                border-bottom: 1px solid rgba(255,255,255,0.1);
                min-height: 60px;
            }}
            .user-info {{ 
                display: flex; 
                align-items: center; 
                gap: 20px;
                font-size: 1em;
                line-height: 1.2;
            }}
            .sidebar-logo {{
                text-align: center;
                font-size: 2.2em;
                font-weight: 300;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                margin-bottom: 15px;
                padding: 5px 0 8px 0;
                border-bottom: 1px solid rgba(76,175,80,0.3);
            }}
            .sidebar-logo .case {{ color: #4caf50; }}
            .sidebar-logo .scope {{ color: white; }}
            .version-badge {{
                font-size: 0.4em;
                background: linear-gradient(145deg, #4caf50, #388e3c);
                color: white;
                padding: 3px 6px;
                border-radius: 6px;
                margin-top: 5px;
                display: inline-block;
                box-shadow: 0 2px 4px rgba(76,175,80,0.3);
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .content {{ padding: 30px; }}
            .menu-item {{ 
                display: block; 
                color: white; 
                text-decoration: none; 
                padding: 12px 16px; 
                margin: 6px 0; 
                border-radius: 12px; 
                background: linear-gradient(145deg, #3949ab, #283593);
                box-shadow: 
                    0 4px 8px rgba(0,0,0,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.1);
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
                font-size: 0.95em;
            }}
            .menu-item:hover {{ 
                background: linear-gradient(145deg, #5c6bc0, #3949ab);
                transform: translateX(5px);
                box-shadow: 
                    0 8px 15px rgba(0,0,0,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.2);
            }}
            .menu-item.active {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
            }}
            .menu-item.placeholder {{ 
                background: linear-gradient(145deg, #424242, #2e2e2e); 
                color: #aaa; 
                cursor: not-allowed;
                opacity: 0.7;
            }}
            .menu-item.placeholder:hover {{
                transform: none;
                box-shadow: 
                    0 4px 8px rgba(0,0,0,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.1);
            }}
            h3.menu-title {{
                font-size: 1.1em;
                margin: 15px 0 8px 0;
                color: #4caf50;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
                border-bottom: 1px solid rgba(76,175,80,0.3);
                padding-bottom: 4px;
            }}
            .logout-btn {{
                background: linear-gradient(145deg, #f44336, #d32f2f);
                color: white !important;
                padding: 8px 16px;
                border-radius: 8px;
                text-decoration: none;
                font-size: 0.9em;
                font-weight: 500;
                box-shadow: 0 4px 8px rgba(244,67,54,0.3);
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .logout-btn:hover {{
                background: linear-gradient(145deg, #ef5350, #f44336);
                box-shadow: 0 6px 12px rgba(244,67,54,0.4);
                transform: translateY(-1px);
                color: white !important;
            }}
            .search-container {{
                margin-bottom: 20px;
                display: flex;
                gap: 15px;
                align-items: center;
            }}
            .search-input {{
                flex: 1;
                padding: 12px 16px;
                border: none;
                border-radius: 8px;
                background: rgba(255,255,255,0.1);
                color: white;
                font-size: 14px;
                box-shadow: inset 0 2px 5px rgba(0,0,0,0.2);
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .search-input::placeholder {{ color: rgba(255,255,255,0.7); }}
            .create-btn {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
                color: white;
                padding: 12px 20px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-weight: 600;
                text-decoration: none;
                transition: all 0.3s ease;
                box-shadow: 0 4px 8px rgba(76,175,80,0.3);
            }}
            .create-btn:hover {{
                background: linear-gradient(145deg, #66bb6a, #4caf50);
                transform: translateY(-1px);
            }}
            .case-table {{
                width: 100%;
                background: linear-gradient(145deg, #3f51b5, #283593);
                border-radius: 15px;
                overflow: hidden;
                box-shadow: 0 8px 20px rgba(0,0,0,0.3);
            }}
            .case-table th, .case-table td {{
                padding: 15px;
                text-align: left;
                border-bottom: 1px solid rgba(255,255,255,0.1);
            }}
            .case-table th {{
                background: #283593;
                font-weight: 600;
                color: white;
            }}
            .case-row {{
                cursor: pointer;
                transition: all 0.3s ease;
            }}
            .case-row:hover {{
                background: rgba(255,255,255,0.1);
            }}
            .case-row.active-case {{
                background: rgba(76,175,80,0.2);
                border-left: 4px solid #4caf50;
            }}
            .priority-low {{ color: #81c784; }}
            .priority-medium {{ color: #ffb74d; }}
            .priority-high {{ color: #ff8a65; }}
            .priority-critical {{ color: #e57373; }}
            .status-open {{ color: #4caf50; }}
            .status-in-progress {{ color: #2196f3; }}
            .status-closed {{ color: #9e9e9e; }}
            .status-archived {{ color: #757575; }}
            .flash-message {{
                padding: 15px 20px;
                margin: 20px 0;
                border-radius: 12px;
                display: flex;
                align-items: center;
                gap: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                animation: slideIn 0.3s ease;
            }}
            .flash-success {{
                background: linear-gradient(145deg, #4caf50, #388e3c);
                border: 1px solid rgba(255,255,255,0.2);
            }}
            .flash-warning {{
                background: linear-gradient(145deg, #ff9800, #f57c00);
                border: 1px solid rgba(255,255,255,0.2);
            }}
            .flash-error {{
                background: linear-gradient(145deg, #f44336, #d32f2f);
                border: 1px solid rgba(255,255,255,0.2);
            }}
            .flash-icon {{ font-size: 1.5em; flex-shrink: 0; }}
            .flash-text {{ flex: 1; font-size: 1em; line-height: 1.4; }}
            .flash-close {{
                background: rgba(255,255,255,0.2);
                border: none;
                color: white;
                font-size: 24px;
                font-weight: bold;
                cursor: pointer;
                width: 32px;
                height: 32px;
                border-radius: 6px;
                display: flex;
                align-items: center;
                justify-content: center;
                transition: all 0.2s ease;
                flex-shrink: 0;
            }}
            .flash-close:hover {{
                background: rgba(255,255,255,0.3);
                transform: scale(1.1);
            }}
            @keyframes slideIn {{
                from {{ opacity: 0; transform: translateY(-10px); }}
                to {{ opacity: 1; transform: translateY(0); }}
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
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
                {flash_messages_html}
                <h1>📁 Case Selection</h1>
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

def render_case_dashboard(case, total_files, indexed_files, processing_files, total_events, total_violations, total_storage):
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
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: linear-gradient(135deg, #1a237e 0%, #3949ab 100%); 
                color: white; 
                margin: 0; 
                display: flex; 
                min-height: 100vh; 
            }}
            .sidebar {{ 
                width: 280px; 
                background: linear-gradient(145deg, #303f9f, #283593); 
                padding: 20px; 
                box-shadow: 
                    5px 0 20px rgba(0,0,0,0.4),
                    inset -1px 0 0 rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
            }}
            .main-content {{ flex: 1; }}
            .header {{ 
                background: linear-gradient(145deg, #283593, #1e88e5); 
                padding: 15px 30px; 
                display: flex; 
                justify-content: space-between; 
                align-items: center;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                border-bottom: 1px solid rgba(255,255,255,0.1);
                min-height: 60px;
            }}
            .case-title {{
                font-size: 1.3em;
                font-weight: 600;
            }}
            .user-info {{ 
                display: flex; 
                align-items: center; 
                gap: 20px;
                font-size: 1em;
                line-height: 1.2;
            }}
            .sidebar-logo {{
                text-align: center;
                font-size: 2.2em;
                font-weight: 300;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
                margin-bottom: 15px;
                padding: 5px 0 8px 0;
                border-bottom: 1px solid rgba(76,175,80,0.3);
            }}
            .sidebar-logo .case {{ color: #4caf50; }}
            .sidebar-logo .scope {{ color: white; }}
            .version-badge {{
                font-size: 0.4em;
                background: linear-gradient(145deg, #4caf50, #388e3c);
                color: white;
                padding: 3px 6px;
                border-radius: 6px;
                margin-top: 5px;
                display: inline-block;
                box-shadow: 0 2px 4px rgba(76,175,80,0.3);
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .content {{ padding: 30px; }}
            .menu-item {{ 
                display: block; 
                color: white; 
                text-decoration: none; 
                padding: 12px 16px; 
                margin: 6px 0; 
                border-radius: 12px; 
                background: linear-gradient(145deg, #3949ab, #283593);
                box-shadow: 
                    0 4px 8px rgba(0,0,0,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.1);
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
                font-size: 0.95em;
            }}
            .menu-item:hover {{ 
                background: linear-gradient(145deg, #5c6bc0, #3949ab);
                transform: translateX(5px);
                box-shadow: 
                    0 8px 15px rgba(0,0,0,0.4),
                    inset 0 1px 0 rgba(255,255,255,0.2);
            }}
            .menu-item.placeholder {{ 
                background: linear-gradient(145deg, #424242, #2e2e2e); 
                color: #aaa; 
                cursor: not-allowed;
                opacity: 0.7;
            }}
            .menu-item.placeholder:hover {{
                transform: none;
                box-shadow: 
                    0 4px 8px rgba(0,0,0,0.3),
                    inset 0 1px 0 rgba(255,255,255,0.1);
            }}
            h3.menu-title {{
                font-size: 1.1em;
                margin: 15px 0 8px 0;
                color: #4caf50;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
                border-bottom: 1px solid rgba(76,175,80,0.3);
                padding-bottom: 4px;
            }}
            .logout-btn {{
                background: linear-gradient(145deg, #f44336, #d32f2f);
                color: white !important;
                padding: 8px 16px;
                border-radius: 8px;
                text-decoration: none;
                font-size: 0.9em;
                font-weight: 500;
                box-shadow: 0 4px 8px rgba(244,67,54,0.3);
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.1);
            }}
            .logout-btn:hover {{
                background: linear-gradient(145deg, #ef5350, #f44336);
                box-shadow: 0 6px 12px rgba(244,67,54,0.4);
                transform: translateY(-1px);
                color: white !important;
            }}
            .flash-message {{
                padding: 15px 20px;
                margin: 20px 0;
                border-radius: 12px;
                display: flex;
                align-items: center;
                gap: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                animation: slideIn 0.3s ease;
            }}
            .flash-success {{ background: linear-gradient(145deg, #4caf50, #388e3c); border: 1px solid rgba(255,255,255,0.2); }}
            .flash-warning {{ background: linear-gradient(145deg, #ff9800, #f57c00); border: 1px solid rgba(255,255,255,0.2); }}
            .flash-error {{ background: linear-gradient(145deg, #f44336, #d32f2f); border: 1px solid rgba(255,255,255,0.2); }}
            .flash-icon {{ font-size: 1.5em; flex-shrink: 0; }}
            .flash-text {{ flex: 1; font-size: 1em; line-height: 1.4; }}
            .flash-close {{ background: rgba(255,255,255,0.2); border: none; color: white; font-size: 24px; font-weight: bold; cursor: pointer; width: 32px; height: 32px; border-radius: 6px; display: flex; align-items: center; justify-content: center; transition: all 0.2s ease; flex-shrink: 0; }}
            .flash-close:hover {{ background: rgba(255,255,255,0.3); transform: scale(1.1); }}
            @keyframes slideIn {{ from {{ opacity: 0; transform: translateY(-10px); }} to {{ opacity: 1; transform: translateY(0); }} }}
            .case-info {{
                background: linear-gradient(145deg, #283593, #1e88e5);
                padding: 20px;
                border-radius: 15px;
                margin-bottom: 25px;
                box-shadow: 0 8px 20px rgba(0,0,0,0.3);
            }}
            .tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 25px; }}
            .tile {{ 
                background: linear-gradient(145deg, #3f51b5, #283593); 
                padding: 25px; 
                border-radius: 15px; 
                box-shadow: 0 8px 20px rgba(0,0,0,0.3);
                transition: all 0.3s ease;
            }}
            .tile:hover {{
                transform: translateY(-3px);
                box-shadow: 0 12px 30px rgba(0,0,0,0.4);
            }}
            .tile h3 {{
                margin-top: 0;
                margin-bottom: 15px;
                font-size: 1.3em;
                text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
            }}
            .actions {{ margin-top: 25px; text-align: center; }}
            .btn {{ 
                background: linear-gradient(145deg, #4caf50, #388e3c); 
                color: white; 
                padding: 12px 24px; 
                text-decoration: none; 
                border-radius: 8px; 
                margin: 0 10px 10px 10px;
                display: inline-block;
                transition: all 0.3s ease;
                font-weight: 600;
                box-shadow: 0 4px 8px rgba(76,175,80,0.3);
            }}
            .btn:hover {{ 
                background: linear-gradient(145deg, #66bb6a, #4caf50); 
                transform: translateY(-1px);
                box-shadow: 0 6px 12px rgba(76,175,80,0.4);
            }}
            .btn-secondary {{ 
                background: linear-gradient(145deg, #2196f3, #1976d2);
                box-shadow: 0 4px 8px rgba(33,150,243,0.3);
            }}
            .btn-secondary:hover {{ 
                background: linear-gradient(145deg, #42a5f5, #2196f3);
                box-shadow: 0 6px 12px rgba(33,150,243,0.4);
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
                    <h2>Case Details</h2>
                    <p><strong>Case Number:</strong> {case.case_number}</p>
                    <p><strong>Description:</strong> {case.description or 'No description provided'}</p>
                    <p><strong>Priority:</strong> {case.priority} | <strong>Status:</strong> {case.status}</p>
                    <p><strong>Created:</strong> {case.created_at.strftime('%Y-%m-%d %H:%M')} by {case.creator.username}</p>
                </div>
                
                <div class="tiles">
                    <div class="tile">
                        <h3>📄 Files</h3>
                        <p><strong>Total Files:</strong> {total_files:,}</p>
                        <p><strong>Indexed:</strong> {indexed_files:,} / {total_files:,}</p>
                        <p><strong>Processing:</strong> {processing_files:,}</p>
                        <p><strong>Storage:</strong> {total_storage / (1024*1024*1024):.2f} GB</p>
                        <a href="/files" class="btn btn-secondary">Manage Files</a>
                    </div>
                    <div class="tile">
                        <h3>📊 Events</h3>
                        <p><strong>Total Events:</strong> {total_events:,}</p>
                        <p><strong>Indexed Files:</strong> {indexed_files:,}</p>
                        <p><strong>Searchable:</strong> {'Yes' if indexed_files > 0 else 'No files indexed yet'}</p>
                        <p><strong>Event IDs:</strong> 100+ Mapped</p>
                        <a href="/search" class="btn btn-secondary">Search Events</a>
                    </div>
                    <div class="tile">
                        <h3>🛡️ SIGMA Rules</h3>
                        <p><strong>Violations Found:</strong> {total_violations:,}</p>
                        <p><strong>Files Scanned:</strong> {indexed_files:,}</p>
                        <p><strong>Rule Database:</strong> Coming Soon</p>
                        <p><strong>Auto-Processing:</strong> In Development</p>
                        <a href="/sigma-rules" class="btn btn-secondary">Manage Rules</a>
                    </div>
                </div>
                
                <div class="actions">
                    <a href="/upload" class="btn">📤 Upload Files</a>
                    <a href="/case/select" class="btn btn-secondary">🔄 Switch Case</a>
                    <a href="/dashboard" class="btn btn-secondary">🏠 Main Dashboard</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

# SIGMA Rules Management
def load_default_sigma_rules():
    """Load built-in SIGMA rules on first run"""
    import hashlib
    
    # Check if we already have built-in rules
    existing_count = SigmaRule.query.filter_by(is_builtin=True).count()
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
        existing = SigmaRule.query.filter_by(rule_hash=rule_hash).first()
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
        admin = User.query.filter_by(username='administrator').first()
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
                    response['message'] = task_result.info.get('status', 'Processing')
                    response['rules_processed'] = task_result.info.get('current', 0)
                    response['total_rules'] = task_result.info.get('total', 0)
                    response['violations_found'] = task_result.info.get('violations', 0)
                else:
                    response['progress'] = 50
                    response['message'] = 'Processing'
            elif task_result.state == 'SUCCESS':
                response['progress'] = 100
                response['message'] = 'Completed'
                # Update DB if status doesn't match
                if case_file.indexing_status != 'Completed':
                    case_file.indexing_status = 'Completed'
                    case_file.celery_task_id = None  # Clear task ID
                    db.session.commit()
            elif task_result.state == 'FAILURE':
                response['progress'] = 0
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
        elif case_file.indexing_status == 'Running Rules':
            response['progress'] = 50
            response['message'] = 'Running Rules (no task tracking)'
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

if __name__ == '__main__':
    print("Starting caseScope 7.1 application...")
    print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print("Initializing database...")
    init_db()
    print("Database initialization completed")
    print("Starting Flask application on 0.0.0.0:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
