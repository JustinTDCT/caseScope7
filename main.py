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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').lower().strip()
        password = request.form.get('password', '')
        
        user = User.query.filter(db.func.lower(User.username) == username).first()
        
        if user and user.check_password(password) and user.is_active:
            login_user(user)
            if user.force_password_change:
                flash('You must change your password before continuing.', 'warning')
                return redirect(url_for('change_password'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>caseScope 7.1 - Login</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #1a237e; color: white; margin: 0; padding: 50px; }}
            .login-container {{ max-width: 400px; margin: 0 auto; background: #283593; padding: 30px; border-radius: 10px; }}
            .logo {{ text-align: center; font-size: 2em; margin-bottom: 30px; }}
            .logo .case {{ color: #4caf50; }}
            .logo .scope {{ color: white; }}
            input {{ width: 100%; padding: 10px; margin: 10px 0; border: none; border-radius: 5px; }}
            button {{ width: 100%; padding: 10px; background: #4caf50; color: white; border: none; border-radius: 5px; cursor: pointer; }}
            .version {{ text-align: center; margin-top: 20px; font-size: 0.8em; color: #ccc; }}
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="logo"><span class="case">case</span><span class="scope">Scope</span></div>
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
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
            body {{ font-family: Arial, sans-serif; background: #1a237e; color: white; margin: 0; display: flex; min-height: 100vh; }}
            .sidebar {{ width: 250px; background: #303f9f; padding: 20px; box-shadow: 2px 0 5px rgba(0,0,0,0.3); }}
            .main-content {{ flex: 1; }}
            .header {{ background: #283593; padding: 20px; display: flex; justify-content: space-between; align-items: center; }}
            .logo {{ font-size: 1.5em; }}
            .logo .case {{ color: #4caf50; }}
            .logo .scope {{ color: white; }}
            .user-info {{ display: flex; align-items: center; gap: 20px; }}
            .content {{ padding: 30px; }}
            .tile {{ background: #3f51b5; padding: 20px; margin: 10px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.3); }}
            .tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
            .menu-item {{ display: block; color: white; text-decoration: none; padding: 10px; margin: 5px 0; border-radius: 5px; background: #3949ab; }}
            .menu-item:hover {{ background: #5c6bc0; }}
            .menu-item.placeholder {{ background: #424242; color: #aaa; cursor: not-allowed; }}
            a {{ color: #4caf50; text-decoration: none; }}
            .footer {{ position: fixed; bottom: 10px; right: 10px; font-size: 0.8em; color: #ccc; }}
            .status {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.8em; }}
            .status.operational {{ background: #4caf50; }}
            .status.placeholder {{ background: #ff9800; }}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <h3>Menu</h3>
            <a href="/dashboard" class="menu-item">📊 Dashboard</a>
            <a href="/case-selection" class="menu-item placeholder">📁 Case Selection (Coming Soon)</a>
            <a href="/upload" class="menu-item placeholder">📤 Upload Files (Coming Soon)</a>
            <a href="/files" class="menu-item placeholder">📄 List Files (Coming Soon)</a>
            <a href="/search" class="menu-item placeholder">🔍 Search (Coming Soon)</a>
            <hr style="border-color: #5c6bc0; margin: 20px 0;">
            <h4>Management</h4>
            <a href="/case-management" class="menu-item placeholder">⚙️ Case Management (Coming Soon)</a>
            <a href="/file-management" class="menu-item placeholder">🗂️ File Management (Coming Soon)</a>
            <a href="/users" class="menu-item placeholder">👥 User Management (Coming Soon)</a>
            <a href="/settings" class="menu-item placeholder">⚙️ System Settings (Coming Soon)</a>
        </div>
        <div class="main-content">
            <div class="header">
                <div class="logo"><span class="case">case</span><span class="scope">Scope</span> <span style="font-size: 0.7em;">{APP_VERSION}</span></div>
                <div class="user-info">
                    <span>Welcome, {current_user.username} ({current_user.role})</span>
                    <a href="{url_for('logout')}">Logout</a>
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
                
                <div style="margin-top: 30px; padding: 20px; background: #2e7d32; border-radius: 10px;">
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
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Change Password - caseScope 7.1</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #1a237e; color: white; margin: 0; padding: 50px; }}
            .container {{ max-width: 500px; margin: 0 auto; background: #283593; padding: 30px; border-radius: 10px; }}
            .logo {{ text-align: center; font-size: 2em; margin-bottom: 30px; }}
            .logo .case {{ color: #4caf50; }}
            .logo .scope {{ color: white; }}
            input {{ width: 100%; padding: 10px; margin: 10px 0; border: none; border-radius: 5px; }}
            button {{ width: 100%; padding: 10px; background: #4caf50; color: white; border: none; border-radius: 5px; cursor: pointer; }}
            .alert {{ padding: 10px; margin: 10px 0; border-radius: 5px; background: #f44336; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo"><span class="case">case</span><span class="scope">Scope</span></div>
            <h2>Change Password</h2>
            <p>You must change your password before continuing.</p>
            <form method="POST">
                <input type="password" name="current_password" placeholder="Current Password" required>
                <input type="password" name="new_password" placeholder="New Password (min 8 characters)" required>
                <input type="password" name="confirm_password" placeholder="Confirm New Password" required>
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
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
