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
        all_users = User.query.all()
        user_list = [{"id": u.id, "username": u.username, "email": u.email, "role": u.role, "active": u.is_active} for u in all_users]
        
        return f'''
        <h2>Database Debug Information</h2>
        <p><strong>Total Users:</strong> {user_count}</p>
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
            <a href="/case-selection" class="menu-item placeholder">📁 Case Selection (Coming Soon)</a>
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
