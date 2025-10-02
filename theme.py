"""
Dark Flat Theme for caseScope 7
Modern, flat design with subtle depth - no gradients, clean professional look
Based on Huntress-style interface
"""

def get_theme_css():
    """
    Returns the complete CSS for the dark flat theme.
    Used by all render functions for consistent styling.
    """
    return '''
        <style>
            /* === ROOT VARIABLES === */
            :root {
                --bg-primary: #1e1e1e;
                --bg-secondary: #2d2d2d;
                --bg-tertiary: #3a3a3a;
                --bg-card: #252525;
                --bg-input: #1a1a1a;
                
                --text-primary: #ffffff;
                --text-secondary: #b0b0b0;
                --text-muted: #808080;
                
                --border-default: #404040;
                --border-light: #4a4a4a;
                
                --accent-green: #4caf50;
                --accent-blue: #2196f3;
                --accent-red: #f44336;
                --accent-orange: #ff9800;
                --accent-purple: #9c27b0;
                
                --shadow-sm: 0 1px 3px rgba(0,0,0,0.3);
                --shadow-md: 0 2px 6px rgba(0,0,0,0.4);
                --shadow-lg: 0 4px 12px rgba(0,0,0,0.5);
            }
            
            /* === BASE LAYOUT === */
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                background: var(--bg-primary);
                color: var(--text-primary);
                margin: 0; 
                display: flex; 
                min-height: 100vh; 
            }
            
            .sidebar { 
                width: 280px; 
                background: var(--bg-secondary);
                padding: 20px; 
                box-shadow: 2px 0 8px rgba(0,0,0,0.4);
                border-right: 1px solid var(--border-default);
            }
            
            .main-content { flex: 1; }
            
            .header { 
                background: var(--bg-secondary);
                padding: 15px 30px; 
                display: flex; 
                justify-content: flex-end; 
                align-items: center;
                box-shadow: var(--shadow-md);
                border-bottom: 1px solid var(--border-default);
                min-height: 60px;
            }
            
            .user-info { 
                display: flex; 
                align-items: center; 
                gap: 20px;
                font-size: 1em;
                line-height: 1.2;
                color: var(--text-secondary);
            }
            
            .content { 
                padding: 30px;
                background: var(--bg-primary);
            }
            
            /* === SIDEBAR LOGO === */
            .sidebar-logo {
                text-align: center;
                font-size: 2.2em;
                font-weight: 300;
                margin-bottom: 15px;
                padding: 5px 0 15px 0;
                border-bottom: 1px solid var(--border-default);
            }
            .sidebar-logo .case { color: var(--accent-green); }
            .sidebar-logo .scope { color: var(--text-primary); }
            
            .version-badge {
                font-size: 0.4em;
                background: var(--accent-green);
                color: white;
                padding: 4px 8px;
                border-radius: 4px;
                margin-top: 5px;
                display: inline-block;
                border: 1px solid rgba(255,255,255,0.1);
            }
            
            /* === MENU ITEMS === */
            .menu-item { 
                display: block; 
                color: var(--text-secondary);
                text-decoration: none; 
                padding: 12px 16px; 
                margin: 4px 0; 
                border-radius: 6px; 
                background: var(--bg-tertiary);
                transition: all 0.2s ease;
                border: 1px solid var(--border-default);
                font-size: 0.95em;
            }
            
            .menu-item:hover { 
                background: var(--bg-card);
                color: var(--text-primary);
                border-color: var(--border-light);
            }
            
            .menu-item.active {
                background: var(--accent-green);
                color: white;
                border-color: var(--accent-green);
            }
            
            .menu-item.placeholder { 
                background: var(--bg-card);
                color: var(--text-muted);
                cursor: not-allowed;
                opacity: 0.6;
            }
            
            .menu-item.placeholder:hover {
                background: var(--bg-card);
                color: var(--text-muted);
            }
            
            h3.menu-title {
                font-size: 1.1em;
                margin: 20px 0 10px 0;
                color: var(--accent-green);
                border-bottom: 1px solid var(--border-default);
                padding-bottom: 6px;
                font-weight: 500;
            }
            
            /* === BUTTONS === */
            .logout-btn {
                background: var(--accent-red);
                color: white !important;
                padding: 8px 16px;
                border-radius: 6px;
                text-decoration: none;
                font-size: 0.9em;
                font-weight: 500;
                transition: all 0.2s ease;
                border: 1px solid rgba(0,0,0,0.2);
            }
            
            .logout-btn:hover {
                background: #e53935;
                color: white !important;
            }
            
            .create-btn, .btn-primary {
                background: var(--accent-blue);
                color: white;
                padding: 12px 20px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-weight: 500;
                text-decoration: none;
                transition: all 0.2s ease;
                display: inline-block;
            }
            
            .create-btn:hover, .btn-primary:hover {
                background: #1976d2;
            }
            
            .btn-success {
                background: var(--accent-green);
                color: white;
                padding: 10px 18px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-weight: 500;
                transition: all 0.2s ease;
            }
            
            .btn-success:hover {
                background: #43a047;
            }
            
            .btn-danger {
                background: var(--accent-red);
                color: white;
                padding: 10px 18px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-weight: 500;
                transition: all 0.2s ease;
            }
            
            .btn-danger:hover {
                background: #e53935;
            }
            
            .btn-warning {
                background: var(--accent-orange);
                color: white;
                padding: 10px 18px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-weight: 500;
                transition: all 0.2s ease;
            }
            
            .btn-warning:hover {
                background: #fb8c00;
            }
            
            .btn-secondary {
                background: var(--bg-tertiary);
                color: var(--text-primary);
                padding: 10px 18px;
                border: 1px solid var(--border-default);
                border-radius: 6px;
                cursor: pointer;
                font-weight: 500;
                transition: all 0.2s ease;
            }
            
            .btn-secondary:hover {
                background: var(--bg-card);
                border-color: var(--border-light);
            }
            
            /* === INPUTS === */
            .search-input, input[type="text"], input[type="password"], input[type="email"], textarea, select {
                padding: 10px 14px;
                border: 1px solid var(--border-default);
                border-radius: 6px;
                background: var(--bg-input);
                color: var(--text-primary);
                font-size: 14px;
                transition: all 0.2s ease;
            }
            
            .search-input:focus, input[type="text"]:focus, input[type="password"]:focus, input[type="email"]:focus, textarea:focus, select:focus {
                outline: none;
                border-color: var(--accent-blue);
                background: #1a1a1a;
            }
            
            .search-input::placeholder, input::placeholder, textarea::placeholder {
                color: var(--text-muted);
            }
            
            /* === TABLES === */
            .case-table, .file-table, .user-table, .audit-table {
                width: 100%;
                background: var(--bg-card);
                border-radius: 8px;
                overflow: hidden;
                box-shadow: var(--shadow-md);
                border: 1px solid var(--border-default);
            }
            
            table {
                width: 100%;
                border-collapse: collapse;
            }
            
            th {
                background: var(--bg-tertiary);
                color: var(--text-primary);
                padding: 14px 16px;
                text-align: left;
                font-weight: 600;
                font-size: 0.9em;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                border-bottom: 2px solid var(--border-default);
            }
            
            td {
                padding: 12px 16px;
                border-bottom: 1px solid var(--border-default);
                color: var(--text-secondary);
            }
            
            tr:last-child td {
                border-bottom: none;
            }
            
            tbody tr {
                transition: background 0.2s ease;
            }
            
            tbody tr:hover {
                background: var(--bg-tertiary);
            }
            
            tr.active-case, tr.selected {
                background: rgba(76, 175, 80, 0.15);
            }
            
            tr.case-row {
                cursor: pointer;
            }
            
            /* === CARDS/TILES === */
            .dashboard-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .tile {
                background: var(--bg-card);
                border-radius: 8px;
                padding: 20px;
                box-shadow: var(--shadow-sm);
                border: 1px solid var(--border-default);
                transition: all 0.2s ease;
            }
            
            .tile:hover {
                box-shadow: var(--shadow-md);
                border-color: var(--border-light);
            }
            
            .tile h3 {
                margin: 0 0 12px 0;
                font-size: 0.95em;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                color: var(--text-secondary);
                font-weight: 500;
            }
            
            .tile-value {
                font-size: 2.2em;
                font-weight: 300;
                color: var(--text-primary);
                margin: 10px 0;
            }
            
            .tile-subtitle {
                font-size: 0.85em;
                color: var(--text-muted);
                margin-top: 8px;
            }
            
            /* === STATUS BADGES === */
            .priority-high, .status-critical {
                background: var(--accent-red);
                color: white;
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 0.85em;
                font-weight: 500;
            }
            
            .priority-medium, .status-active {
                background: var(--accent-orange);
                color: white;
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 0.85em;
                font-weight: 500;
            }
            
            .priority-low, .status-open {
                background: var(--accent-blue);
                color: white;
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 0.85em;
                font-weight: 500;
            }
            
            .status-closed, .status-complete {
                background: var(--bg-tertiary);
                color: var(--text-muted);
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 0.85em;
                font-weight: 500;
            }
            
            .status-archived {
                background: var(--bg-card);
                color: var(--text-muted);
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 0.85em;
                font-weight: 500;
            }
            
            /* === FLASH MESSAGES === */
            .flash-container {
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 10000;
                max-width: 400px;
            }
            
            .flash-message {
                background: var(--bg-card);
                border: 1px solid var(--border-default);
                border-radius: 6px;
                padding: 14px 18px;
                margin-bottom: 12px;
                display: flex;
                align-items: center;
                gap: 12px;
                box-shadow: var(--shadow-lg);
                animation: slideIn 0.3s ease;
            }
            
            @keyframes slideIn {
                from { transform: translateX(400px); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            
            .flash-success {
                border-left: 4px solid var(--accent-green);
            }
            
            .flash-error {
                border-left: 4px solid var(--accent-red);
            }
            
            .flash-warning {
                border-left: 4px solid var(--accent-orange);
            }
            
            .flash-info {
                border-left: 4px solid var(--accent-blue);
            }
            
            .flash-icon {
                font-size: 1.2em;
            }
            
            .flash-text {
                flex: 1;
                color: var(--text-primary);
                font-size: 0.9em;
            }
            
            .flash-close {
                background: none;
                border: none;
                color: var(--text-muted);
                font-size: 1.4em;
                cursor: pointer;
                padding: 0;
                line-height: 1;
                transition: color 0.2s ease;
            }
            
            .flash-close:hover {
                color: var(--text-primary);
            }
            
            /* === HEADINGS === */
            h1 {
                font-size: 2em;
                font-weight: 300;
                color: var(--text-primary);
                margin: 0 0 25px 0;
                border-bottom: 1px solid var(--border-default);
                padding-bottom: 15px;
            }
            
            h2 {
                font-size: 1.6em;
                font-weight: 400;
                color: var(--text-primary);
                margin: 25px 0 15px 0;
            }
            
            h3 {
                font-size: 1.3em;
                font-weight: 500;
                color: var(--text-secondary);
                margin: 20px 0 10px 0;
            }
            
            /* === FORMS === */
            .form-group {
                margin-bottom: 20px;
            }
            
            .form-group label {
                display: block;
                margin-bottom: 6px;
                color: var(--text-secondary);
                font-size: 0.9em;
                font-weight: 500;
            }
            
            .form-group input, .form-group select, .form-group textarea {
                width: 100%;
            }
            
            /* === SEARCH CONTAINERS === */
            .search-container {
                margin-bottom: 20px;
                display: flex;
                gap: 15px;
                align-items: center;
            }
            
            .search-input {
                flex: 1;
            }
            
            /* === PROGRESS INDICATORS === */
            .progress-text {
                color: var(--text-secondary);
                font-size: 0.9em;
                font-family: 'Consolas', 'Monaco', monospace;
            }
            
            /* === SCROLLBAR STYLING === */
            ::-webkit-scrollbar {
                width: 10px;
                height: 10px;
            }
            
            ::-webkit-scrollbar-track {
                background: var(--bg-primary);
            }
            
            ::-webkit-scrollbar-thumb {
                background: var(--bg-tertiary);
                border-radius: 5px;
            }
            
            ::-webkit-scrollbar-thumb:hover {
                background: var(--border-light);
            }
            
            /* === UTILITY CLASSES === */
            .text-center { text-align: center; }
            .text-right { text-align: right; }
            .mt-1 { margin-top: 10px; }
            .mt-2 { margin-top: 20px; }
            .mt-3 { margin-top: 30px; }
            .mb-1 { margin-bottom: 10px; }
            .mb-2 { margin-bottom: 20px; }
            .mb-3 { margin-bottom: 30px; }
            .gap-1 { gap: 10px; }
            .gap-2 { gap: 20px; }
            .flex { display: flex; }
            .flex-wrap { flex-wrap: wrap; }
            .justify-between { justify-content: space-between; }
            .align-center { align-items: center; }
        </style>
    '''

