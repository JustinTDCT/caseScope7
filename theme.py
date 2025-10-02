"""
Dark Theme for caseScope 7 - Based on v7.0 styling
Clean, professional dark interface
"""

def get_theme_css():
    """
    Returns the complete CSS for the dark theme.
    Built from scratch based on v7.0 design patterns.
    """
    return '''
        <style>
            /* === RESET & BASE === */
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            html, body {
                height: 100%;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            
            body {
                background: #1a1a1a;
                color: #e0e0e0;
                display: flex;
                flex-direction: column;
                min-height: 100vh;
            }
            
            /* === LAYOUT STRUCTURE === */
            .page-container {
                display: flex;
                flex: 1;
            }
            
            .sidebar {
                width: 260px;
                background: #252525;
                padding: 20px;
                border-right: 1px solid #333;
                flex-shrink: 0;
            }
            
            .main-content {
                flex: 1;
                display: flex;
                flex-direction: column;
            }
            
            .header {
                background: #252525;
                padding: 15px 30px;
                border-bottom: 1px solid #333;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .content {
                flex: 1;
                padding: 30px;
                overflow-y: auto;
            }
            
            .footer {
                background: #252525;
                padding: 12px 30px;
                border-top: 1px solid #333;
                text-align: right;
                font-size: 0.85em;
                color: #888;
            }
            
            .footer a {
                color: #4a90e2;
                text-decoration: none;
            }
            
            .footer a:hover {
                text-decoration: underline;
            }
            
            /* === SIDEBAR === */
            .sidebar-logo {
                text-align: center;
                font-size: 2em;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 1px solid #333;
            }
            
            .sidebar-logo .case {
                color: #4caf50;
                font-weight: 300;
            }
            
            .sidebar-logo .scope {
                color: #e0e0e0;
                font-weight: 300;
            }
            
            .version-badge {
                display: inline-block;
                background: #4caf50;
                color: white;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 0.4em;
                margin-top: 5px;
            }
            
            .menu-title {
                color: #4caf50;
                font-size: 0.9em;
                font-weight: 600;
                text-transform: uppercase;
                margin: 20px 0 10px 0;
                letter-spacing: 0.5px;
            }
            
            .menu-item {
                display: block;
                color: #b0b0b0;
                text-decoration: none;
                padding: 10px 15px;
                margin: 3px 0;
                border-radius: 4px;
                background: #2a2a2a;
                transition: all 0.2s;
                font-size: 0.95em;
            }
            
            .menu-item:hover {
                background: #333;
                color: #e0e0e0;
            }
            
            .menu-item.active {
                background: #4caf50;
                color: white;
            }
            
            /* === HEADER === */
            .user-info {
                display: flex;
                align-items: center;
                gap: 20px;
                color: #b0b0b0;
                font-size: 0.9em;
            }
            
            .logout-btn {
                background: #d32f2f;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                text-decoration: none;
                font-size: 0.9em;
                transition: background 0.2s;
            }
            
            .logout-btn:hover {
                background: #b71c1c;
            }
            
            /* === TYPOGRAPHY === */
            h1 {
                font-size: 2em;
                font-weight: 300;
                color: #e0e0e0;
                margin-bottom: 30px;
                padding-bottom: 15px;
                border-bottom: 1px solid #333;
            }
            
            h2 {
                font-size: 1.5em;
                font-weight: 400;
                color: #e0e0e0;
                margin: 25px 0 15px 0;
            }
            
            h3 {
                font-size: 1.2em;
                font-weight: 500;
                color: #b0b0b0;
                margin: 20px 0 10px 0;
            }
            
            p {
                line-height: 1.6;
                color: #b0b0b0;
                margin-bottom: 15px;
            }
            
            /* === FORMS & INPUTS === */
            input[type="text"],
            input[type="password"],
            input[type="email"],
            textarea,
            select {
                width: 100%;
                padding: 10px 12px;
                background: #2a2a2a;
                border: 1px solid #444;
                border-radius: 4px;
                color: #e0e0e0;
                font-size: 14px;
                font-family: inherit;
            }
            
            input:focus,
            textarea:focus,
            select:focus {
                outline: none;
                border-color: #4a90e2;
                background: #2f2f2f;
            }
            
            input::placeholder,
            textarea::placeholder {
                color: #666;
            }
            
            label {
                display: block;
                color: #b0b0b0;
                font-size: 0.9em;
                margin-bottom: 5px;
                font-weight: 500;
            }
            
            /* === BUTTONS === */
            button,
            .btn,
            input[type="submit"],
            input[type="button"] {
                background: #3a3a3a;
                color: #e0e0e0;
                padding: 10px 20px;
                border: 1px solid #555;
                border-radius: 4px;
                cursor: pointer;
                font-size: 14px;
                font-family: inherit;
                text-decoration: none;
                display: inline-block;
                transition: all 0.2s;
            }
            
            button:hover,
            .btn:hover,
            input[type="submit"]:hover,
            input[type="button"]:hover {
                background: #454545;
                border-color: #666;
            }
            
            button:disabled {
                opacity: 0.5;
                cursor: not-allowed;
            }
            
            /* Button Colors */
            .btn-primary {
                background: #1565c0;
                border-color: #1565c0;
                color: white;
            }
            
            .btn-primary:hover {
                background: #0d47a1;
                border-color: #0d47a1;
            }
            
            .btn-success {
                background: #2e7d32;
                border-color: #2e7d32;
                color: white;
            }
            
            .btn-success:hover {
                background: #1b5e20;
                border-color: #1b5e20;
            }
            
            .btn-danger {
                background: #c62828;
                border-color: #c62828;
                color: white;
            }
            
            .btn-danger:hover {
                background: #b71c1c;
                border-color: #b71c1c;
            }
            
            .btn-warning {
                background: #ef6c00;
                border-color: #ef6c00;
                color: white;
            }
            
            .btn-warning:hover {
                background: #e65100;
                border-color: #e65100;
            }
            
            /* === TABLES === */
            table {
                width: 100%;
                border-collapse: collapse;
                background: #252525;
                border-radius: 4px;
                overflow: hidden;
            }
            
            thead {
                background: #2a2a2a;
            }
            
            th {
                padding: 12px 15px;
                text-align: left;
                font-weight: 600;
                color: #e0e0e0;
                font-size: 0.9em;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                border-bottom: 2px solid #333;
            }
            
            td {
                padding: 12px 15px;
                color: #b0b0b0;
                border-bottom: 1px solid #2a2a2a;
            }
            
            tbody tr:hover {
                background: #2a2a2a;
            }
            
            tbody tr:last-child td {
                border-bottom: none;
            }
            
            /* === CARDS & TILES === */
            .tile,
            .card {
                background: #252525;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 20px;
                margin-bottom: 20px;
            }
            
            .tile h3,
            .card h3 {
                margin-top: 0;
                color: #888;
                font-size: 0.85em;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            .tile-value {
                font-size: 2.5em;
                font-weight: 300;
                color: #e0e0e0;
                margin: 10px 0;
            }
            
            /* === DASHBOARD GRID === */
            .dashboard-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            /* === BADGES === */
            .badge {
                display: inline-block;
                padding: 4px 10px;
                border-radius: 3px;
                font-size: 0.85em;
                font-weight: 600;
            }
            
            .badge-success {
                background: #2e7d32;
                color: white;
            }
            
            .badge-danger {
                background: #c62828;
                color: white;
            }
            
            .badge-warning {
                background: #ef6c00;
                color: white;
            }
            
            .badge-info {
                background: #1565c0;
                color: white;
            }
            
            /* Severity badges */
            .severity-critical {
                background: #c62828;
                color: white;
            }
            
            .severity-high {
                background: #ef6c00;
                color: white;
            }
            
            .severity-medium {
                background: #ffa000;
                color: #000;
            }
            
            .severity-low {
                background: #1565c0;
                color: white;
            }
            
            /* === ALERTS/FLASH === */
            .alert {
                padding: 12px 15px;
                border-radius: 4px;
                margin-bottom: 15px;
                border-left: 4px solid;
            }
            
            .alert-success {
                background: rgba(46, 125, 50, 0.1);
                border-color: #2e7d32;
                color: #66bb6a;
            }
            
            .alert-error {
                background: rgba(198, 40, 40, 0.1);
                border-color: #c62828;
                color: #ef5350;
            }
            
            .alert-warning {
                background: rgba(239, 108, 0, 0.1);
                border-color: #ef6c00;
                color: #ff9800;
            }
            
            .alert-info {
                background: rgba(21, 101, 192, 0.1);
                border-color: #1565c0;
                color: #42a5f5;
            }
            
            /* === LOGIN PAGE === */
            .login-container {
                max-width: 400px;
                margin: 100px auto;
                padding: 40px;
                background: #252525;
                border: 1px solid #333;
                border-radius: 4px;
            }
            
            .login-container .logo {
                text-align: center;
                font-size: 2.5em;
                margin-bottom: 30px;
            }
            
            .login-container .logo .case {
                color: #4caf50;
            }
            
            .login-container .logo .scope {
                color: #e0e0e0;
            }
            
            .login-container form {
                margin-top: 25px;
            }
            
            .login-container input {
                margin-bottom: 15px;
            }
            
            .login-container button {
                width: 100%;
                background: #4caf50;
                border-color: #4caf50;
                color: white;
                padding: 12px;
                font-size: 16px;
            }
            
            .login-container button:hover {
                background: #388e3c;
                border-color: #388e3c;
            }
            
            .login-container .version {
                text-align: center;
                margin-top: 20px;
                font-size: 0.85em;
                color: #666;
            }
            
            /* === UPLOAD PAGE === */
            .upload-container {
                max-width: 800px;
                margin: 0 auto;
            }
            
            .upload-info {
                background: #252525;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 20px;
                margin-bottom: 25px;
            }
            
            .upload-info h3 {
                margin-top: 0;
                color: #e0e0e0;
            }
            
            .upload-info ul {
                list-style: none;
                padding: 0;
            }
            
            .upload-info li {
                padding: 6px 0;
                color: #b0b0b0;
            }
            
            .upload-info li:before {
                content: "• ";
                color: #4caf50;
                font-weight: bold;
                margin-right: 8px;
            }
            
            .upload-zone {
                background: #252525;
                border: 2px dashed #444;
                border-radius: 4px;
                padding: 60px 40px;
                text-align: center;
                cursor: pointer;
                transition: all 0.3s;
            }
            
            .upload-zone:hover {
                border-color: #4a90e2;
                background: #2a2a2a;
            }
            
            .upload-zone.dragover {
                border-color: #4caf50;
                background: rgba(76, 175, 80, 0.1);
            }
            
            .upload-icon {
                font-size: 4em;
                color: #666;
                margin-bottom: 15px;
            }
            
            .upload-text {
                font-size: 1.2em;
                color: #b0b0b0;
                margin-bottom: 8px;
            }
            
            .upload-subtext {
                font-size: 0.9em;
                color: #666;
            }
            
            /* === SEARCH PAGE === */
            .search-container {
                max-width: 1200px;
                margin: 0 auto;
            }
            
            .search-box {
                background: #252525;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 25px;
                margin-bottom: 25px;
            }
            
            .search-box h3 {
                margin-top: 0;
                color: #e0e0e0;
            }
            
            .search-controls {
                display: flex;
                gap: 15px;
                margin-bottom: 15px;
                align-items: center;
                flex-wrap: wrap;
            }
            
            .search-controls input[type="text"] {
                flex: 1;
                min-width: 300px;
            }
            
            .search-controls select {
                min-width: 180px;
            }
            
            .search-controls label {
                display: flex;
                align-items: center;
                gap: 8px;
                margin-bottom: 0;
            }
            
            .search-actions {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
            }
            
            /* === UTILITY === */
            .text-center {
                text-align: center;
            }
            
            .text-right {
                text-align: right;
            }
            
            .mt-1 { margin-top: 10px; }
            .mt-2 { margin-top: 20px; }
            .mt-3 { margin-top: 30px; }
            .mb-1 { margin-bottom: 10px; }
            .mb-2 { margin-bottom: 20px; }
            .mb-3 { margin-bottom: 30px; }
            
            .flex {
                display: flex;
            }
            
            .flex-wrap {
                flex-wrap: wrap;
            }
            
            .gap-1 { gap: 10px; }
            .gap-2 { gap: 20px; }
            
            /* === SCROLLBAR === */
            ::-webkit-scrollbar {
                width: 10px;
                height: 10px;
            }
            
            ::-webkit-scrollbar-track {
                background: #1a1a1a;
            }
            
            ::-webkit-scrollbar-thumb {
                background: #3a3a3a;
                border-radius: 5px;
            }
            
            ::-webkit-scrollbar-thumb:hover {
                background: #4a4a4a;
            }
        </style>
    '''
