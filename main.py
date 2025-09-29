#!/usr/bin/env python3
"""
caseScope 7.1.1 - Main Application Entry Point
Copyright (c) 2025 Justin Dube <casescope@thedubes.net>
"""

import os
import sys
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from datetime import datetime

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
    indexing_status = db.Column(db.String(20), default='Uploaded')  # Uploaded, Indexing, Running Rules, Completed, Failed
    
    # Relationships
    case = db.relationship('Case', backref='files')
    uploader = db.relationship('User', backref='uploaded_files')
    
    def __repr__(self):
        return f'<CaseFile {self.original_filename} in Case {self.case_id}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
                case_dir = f"/opt/casescope/upload/{new_case.id}"
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
    case = Case.query.get_or_404(case_id)
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
    
    case = Case.query.get_or_404(active_case_id)
    return render_case_dashboard(case)

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
    
    case = Case.query.get_or_404(active_case_id)
    
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
                    flash(f'File {file.filename} already exists (duplicate hash).', 'warning')
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
                flash(f'Successfully uploaded {success_count} file(s).', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Database error: {str(e)}', 'error')
        
        if error_count > 0:
            flash(f'{error_count} file(s) failed to upload.', 'warning')
        
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
    
    case = Case.query.get_or_404(active_case_id)
    files = CaseFile.query.filter_by(case_id=case.id, is_deleted=False).order_by(CaseFile.uploaded_at.desc()).all()
    
    return render_file_list(case, files)

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
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>caseScope 7.1 - Dashboard</title>
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
            
            <h3 class="menu-title">Navigation</h3>
            <a href="/dashboard" class="menu-item">📊 Dashboard</a>
            <a href="/case/select" class="menu-item">📁 Case Selection</a>
            <a href="/upload" class="menu-item">📤 Upload Files</a>
            <a href="/files" class="menu-item">📄 List Files</a>
            <a href="/search" class="menu-item placeholder">🔍 Search (Coming Soon)</a>
            
            <h3 class="menu-title">Management</h3>
            <a href="/case-management" class="menu-item placeholder">⚙️ Case Management (Coming Soon)</a>
            <a href="/file-management" class="menu-item placeholder">🗂️ File Management (Coming Soon)</a>
            <a href="/users" class="menu-item placeholder">👥 User Management (Coming Soon)</a>
            <a href="/settings" class="menu-item placeholder">⚙️ System Settings (Coming Soon)</a>
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
                        <h3>🔧 System Status</h3>
                        <p><span class="status operational">✓ OpenSearch: Running</span></p>
                        <p><span class="status operational">✓ Redis: Running</span></p>
                        <p><span class="status operational">✓ Web Server: Running</span></p>
                        <p><span class="status placeholder">⏳ Full Features: In Development</span></p>
                    </div>
                    <div class="tile">
                        <h3>📊 System Information</h3>
                        <p>OS: Ubuntu Server</p>
                        <p>caseScope: {APP_VERSION}</p>
                        <p>Installation: Complete ✓</p>
                        <p>Database: Initialized ✓</p>
                    </div>
                    <div class="tile">
                        <h3>📈 Cases & Files</h3>
                        <p>Total Cases: 0 (Coming Soon)</p>
                        <p>Total Files: 0 (Coming Soon)</p>
                        <p>Total Events: 0 (Coming Soon)</p>
                        <p>Storage Used: 0 MB (Coming Soon)</p>
                    </div>
                    <div class="tile">
                        <h3>🛡️ SIGMA Rules</h3>
                        <p>Status: Ready for Implementation</p>
                        <p>Last Update: Not Yet Configured</p>
                        <p>Rule Processing: Coming Soon</p>
                        <p><em>Note: Forensic features in development</em></p>
                    </div>
                </div>
                
                <div class="success-banner">
                    <h3>🎉 Installation Successful!</h3>
                    <p>caseScope 7.1 has been successfully installed and all core services are running.</p>
                    <p>This UI demonstrates the installation is working. Forensic features (case management, file processing, search) will be implemented in future releases.</p>
                    <p><strong>Default Login:</strong> administrator / ChangeMe! (password change required on first login)</p>
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
            
            <h3 class="menu-title">Navigation</h3>
            <a href="/dashboard" class="menu-item">📊 Dashboard</a>
            <a href="/case/select" class="menu-item">📁 Case Selection</a>
            <a href="/upload" class="menu-item active">📤 Upload Files</a>
            <a href="/files" class="menu-item">📄 List Files</a>
            <a href="/search" class="menu-item placeholder">🔍 Search (Coming Soon)</a>
            
            <h3 class="menu-title">Management</h3>
            <a href="/case-management" class="menu-item placeholder">⚙️ Case Management (Coming Soon)</a>
            <a href="/file-management" class="menu-item placeholder">🗂️ File Management (Coming Soon)</a>
            <a href="/users" class="menu-item placeholder">👥 User Management (Coming Soon)</a>
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
    file_rows = ""
    for file in files:
        file_size_mb = file.file_size / (1024 * 1024)
        status_class = file.indexing_status.lower().replace(' ', '-')
        
        # Determine status display with progress
        if file.indexing_status == 'Uploaded':
            status_display = 'Uploaded/Pending'
            status_class = 'uploaded'
        elif file.indexing_status == 'Indexing':
            # TODO: Get actual progress from indexing worker
            progress = 0  # Placeholder
            status_display = f'Indexing ({progress}%)'
            status_class = 'indexing'
        elif file.indexing_status == 'Running Rules':
            # TODO: Get actual progress from rules worker
            progress = 0  # Placeholder
            status_display = f'Running Rules ({progress}%)'
            status_class = 'running-rules'
        elif file.indexing_status == 'Completed':
            status_display = 'Completed'
            status_class = 'completed'
        elif file.indexing_status == 'Failed':
            status_display = 'Failed'
            status_class = 'failed'
        else:
            status_display = file.indexing_status
        
        # Event count display
        if file.event_count > 0:
            events_display = f'{file.event_count:,}'
        else:
            events_display = '-'
        
        # Violations count (placeholder for now)
        # TODO: Add violations_count field to CaseFile model
        violations_display = '-'
        
        # Build action buttons based on user role
        actions = f'<button class="btn-action btn-info" onclick="showFileDetails({file.id})">📋 Details</button>'
        
        if file.indexing_status == 'Completed':
            actions += f' <button class="btn-action btn-reindex" onclick="confirmReindex({file.id})">🔄 Re-index</button>'
            actions += f' <button class="btn-action btn-rules" onclick="confirmRerunRules({file.id})">⚡ Re-run Rules</button>'
        
        if current_user.role == 'administrator':
            actions += f' <button class="btn-action btn-delete" onclick="confirmDelete({file.id}, \'{file.original_filename}\')">🗑️ Delete</button>'
        
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
                padding: 15px;
                text-align: left;
                border-bottom: 1px solid rgba(255,255,255,0.1);
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
                padding: 6px 10px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-size: 11px;
                margin: 2px;
                transition: all 0.2s ease;
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
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            <h3 class="menu-title">Navigation</h3>
            <a href="/dashboard" class="menu-item">📊 Dashboard</a>
            <a href="/case/select" class="menu-item">📁 Case Selection</a>
            <a href="/upload" class="menu-item">📤 Upload Files</a>
            <a href="/files" class="menu-item active">📄 List Files</a>
            <a href="/search" class="menu-item placeholder">🔍 Search (Coming Soon)</a>
            
            <h3 class="menu-title">Management</h3>
            <a href="/case-management" class="menu-item placeholder">⚙️ Case Management (Coming Soon)</a>
            <a href="/file-management" class="menu-item placeholder">🗂️ File Management (Coming Soon)</a>
            <a href="/users" class="menu-item placeholder">👥 User Management (Coming Soon)</a>
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
                <h1>📄 Case Files</h1>
                <p>Files uploaded to: {case.name}</p>
                
                <div style="margin: 20px 0;">
                    <a href="/upload" class="btn">📤 Upload Files</a>
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
                    alert('Re-indexing not yet implemented. File ID: ' + fileId);
                    // TODO: POST to /files/reindex/<fileId>
                }}
            }}
            
            function confirmRerunRules(fileId) {{
                if (confirm('Re-run SIGMA rules on this file? This will discard existing rule tags and re-scan all events.')) {{
                    alert('Rule re-run not yet implemented. File ID: ' + fileId);
                    // TODO: POST to /files/rerun-rules/<fileId>
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
        </script>
    </body>
    </html>
    '''

def render_case_form():
    """Render case creation form"""
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
                padding: 0; 
                min-height: 100vh; 
                display: flex; 
                align-items: center; 
                justify-content: center;
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
    </body>
    </html>
    '''

def render_case_selection(cases, active_case_id):
    """Render case selection page with integrated layout"""
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
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="sidebar-logo">
                <span class="case">case</span><span class="scope">Scope</span>
                <div class="version-badge">{APP_VERSION}</div>
            </div>
            
            <h3 class="menu-title">Navigation</h3>
            <a href="/dashboard" class="menu-item">📊 Dashboard</a>
            <a href="/case/select" class="menu-item active">📁 Case Selection</a>
            <a href="/upload" class="menu-item placeholder">📤 Upload Files (Coming Soon)</a>
            <a href="/files" class="menu-item placeholder">📄 List Files (Coming Soon)</a>
            <a href="/search" class="menu-item placeholder">🔍 Search (Coming Soon)</a>
            
            <h3 class="menu-title">Management</h3>
            <a href="/case-management" class="menu-item placeholder">⚙️ Case Management (Coming Soon)</a>
            <a href="/file-management" class="menu-item placeholder">🗂️ File Management (Coming Soon)</a>
            <a href="/users" class="menu-item placeholder">👥 User Management (Coming Soon)</a>
            <a href="/settings" class="menu-item placeholder">⚙️ System Settings (Coming Soon)</a>
        </div>
        <div class="main-content">
            <div class="header">
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            <div class="content">
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

def render_case_dashboard(case):
    """Render case-specific dashboard with integrated layout"""
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
            
            <h3 class="menu-title">Navigation</h3>
            <a href="/dashboard" class="menu-item">📊 Dashboard</a>
            <a href="/case/select" class="menu-item">📁 Case Selection</a>
            <a href="/upload" class="menu-item">📤 Upload Files</a>
            <a href="/files" class="menu-item">📄 List Files</a>
            <a href="/search" class="menu-item placeholder">🔍 Search (Coming Soon)</a>
            
            <h3 class="menu-title">Management</h3>
            <a href="/case-management" class="menu-item placeholder">⚙️ Case Management (Coming Soon)</a>
            <a href="/file-management" class="menu-item placeholder">🗂️ File Management (Coming Soon)</a>
            <a href="/users" class="menu-item placeholder">👥 User Management (Coming Soon)</a>
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
                        <p><strong>Total Files:</strong> {case.file_count}</p>
                        <p><strong>Storage Used:</strong> {case.storage_size / (1024*1024):.1f} MB</p>
                        <a href="/files" class="btn btn-secondary">View Files</a>
                    </div>
                    <div class="tile">
                        <h3>📊 Events</h3>
                        <p><strong>Total Events:</strong> {case.total_events:,}</p>
                        <p><strong>Indexed:</strong> Coming Soon</p>
                        <a href="/search" class="btn btn-secondary">Search Events</a>
                    </div>
                    <div class="tile">
                        <h3>🛡️ Violations</h3>
                        <p><strong>SIGMA Hits:</strong> Coming Soon</p>
                        <p><strong>Last Scan:</strong> Not Yet Run</p>
                        <a href="#" class="btn btn-secondary">View Violations</a>
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

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        
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

if __name__ == '__main__':
    print("Starting caseScope 7.1 application...")
    print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print("Initializing database...")
    init_db()
    print("Database initialization completed")
    print("Starting Flask application on 0.0.0.0:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
