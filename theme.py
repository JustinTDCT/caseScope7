"""
Dark Theme for caseScope 7 - Based on v7.0 style.css
Adapted from template-based system to render-based system
Converted CSS variables to actual values for inline styles
"""

def get_theme_css():
    """
    Returns the complete CSS for the dark theme.
    Based on v7.0 style.css but adapted for render-based system (no CSS variables needed).
    """
    return '''
        <style>
            /* caseScope Dark Theme - v7.0 Based */
            /* Copyright 2025 Justin Dube */
            
            /* === RESET & BASE === */
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            html, body {
                height: 100%;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            }
            
            body {
                background-color: #0f172a;
                color: #f8fafc;
                line-height: 1.6;
                display: flex;
                min-height: 100vh;
                overflow: hidden;
            }
            
            /* === SIDEBAR === */
            .sidebar {
                width: 280px;
                background: #0f172a;
                border-right: 1px solid #334155;
                padding: 1rem;
                overflow-y: auto;
                display: flex;
                flex-direction: column;
                gap: 1.5rem;
                box-shadow: inset -1px 0 0 rgba(255, 255, 255, 0.1), 2px 0 4px rgba(0, 0, 0, 0.3);
            }
            
            .sidebar-logo {
                text-align: center;
                font-size: 1.8rem;
                font-weight: bold;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 0;
                padding-bottom: 1rem;
                border-bottom: 1px solid #334155;
            }
            
            .sidebar-logo .case {
                color: #10b981;
            }
            
            .sidebar-logo .scope {
                color: #f8fafc;
            }
            
            .version-badge {
                font-size: 0.75rem;
                color: #cbd5e1;
                font-weight: normal;
                margin-left: 0.5rem;
                background: #10b981;
                color: white;
                padding: 0.2rem 0.5rem;
                border-radius: 4px;
                font-weight: bold;
                display: inline-block;
                margin-top: 0.5rem;
            }
            
            .menu-title {
                font-size: 0.8rem;
                font-weight: 600;
                color: #cbd5e1;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-bottom: 0.5rem;
            }
            
            .menu-item {
                display: flex;
                align-items: center;
                gap: 0.75rem;
                padding: 0.75rem 1rem;
                color: #f8fafc;
                text-decoration: none;
                border-radius: 8px;
                transition: all 0.3s ease;
                font-size: 0.9rem;
                background: transparent;
            }
            
            .menu-item:hover {
                background: #1e293b;
                transform: translateX(4px);
            }
            
            .menu-item.active {
                background: #3b82f6;
                color: white;
            }
            
            .menu-item.placeholder {
                opacity: 0.5;
                cursor: not-allowed;
            }
            
            /* === MAIN CONTENT AREA === */
            .main-content {
                flex: 1;
                display: flex;
                flex-direction: column;
                overflow: hidden;
            }
            
            /* === HEADER === */
            .header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 1rem 2rem;
                background: #1e293b;
                border-bottom: 1px solid #334155;
                z-index: 1000;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1), inset 0 -1px 0 rgba(0, 0, 0, 0.4);
                background: linear-gradient(180deg, rgba(255, 255, 255, 0.03) 0%, #1e293b 50%, rgba(0, 0, 0, 0.05) 100%);
            }
            
            .header h1 {
                font-size: 1.5rem;
                font-weight: 400;
                color: #f8fafc;
                margin: 0;
                padding: 0;
                border: none;
            }
            
            .header-left .logo {
                font-size: 1.8rem;
                font-weight: bold;
                display: flex;
                align-items: center;
                gap: 0;
            }
            
            .logo-case {
                color: #10b981;
            }
            
            .logo-scope {
                color: #f8fafc;
            }
            
            .header-right {
                display: flex;
                align-items: center;
                gap: 1rem;
            }
            
            .header-info {
                display: flex;
                align-items: center;
                gap: 1rem;
            }
            
            .datetime {
                color: #cbd5e1;
                font-size: 0.9rem;
            }
            
            .user-info {
                display: flex;
                flex-direction: column;
                align-items: flex-end;
                font-size: 0.9rem;
            }
            
            .username {
                color: #f8fafc;
                font-weight: 600;
            }
            
            .role {
                color: #cbd5e1;
                font-size: 0.8rem;
            }
            
            .logout-btn {
                background: #ef4444;
                color: white;
                text-decoration: none;
                padding: 0.5rem 1rem;
                border-radius: 8px;
                font-size: 0.9rem;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                gap: 0.5rem;
                border: none;
                cursor: pointer;
            }
            
            .logout-btn:hover {
                background: #dc2626;
                transform: translateY(-1px);
            }
            
            /* === CONTENT === */
            .content {
                flex: 1;
                padding: 2rem;
                overflow-y: auto;
                background: #0f172a;
            }
            
            /* === FOOTER === */
            .footer {
                padding: 1rem 2rem;
                background: #1e293b;
                border-top: 1px solid #334155;
                color: #cbd5e1;
                font-size: 0.875rem;
            }
            
            .footer-content {
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .footer a {
                color: #3b82f6;
                text-decoration: none;
            }
            
            .footer a:hover {
                text-decoration: underline;
            }
            
            /* === TYPOGRAPHY === */
            h1 {
                font-size: 1.8rem;
                font-weight: 400;
                color: #f8fafc;
                margin-bottom: 1.5rem;
                padding-bottom: 0.75rem;
                border-bottom: 1px solid #334155;
            }
            
            h2 {
                font-size: 1.5rem;
                font-weight: 500;
                color: #f8fafc;
                margin: 1.5rem 0 1rem 0;
            }
            
            h3 {
                font-size: 1.2rem;
                font-weight: 500;
                color: #cbd5e1;
                margin: 1rem 0 0.5rem 0;
            }
            
            h4 {
                font-size: 1rem;
                font-weight: 600;
                color: #cbd5e1;
                margin: 0.75rem 0 0.5rem 0;
            }
            
            p {
                line-height: 1.6;
                color: #cbd5e1;
                margin-bottom: 1rem;
            }
            
            /* === FORMS & INPUTS === */
            input[type="text"],
            input[type="password"],
            input[type="email"],
            input[type="number"],
            input[type="date"],
            input[type="datetime-local"],
            input[type="file"],
            textarea,
            select {
                width: 100%;
                padding: 0.75rem 1rem;
                border: 1px solid #334155;
                border-radius: 8px;
                background: #1e293b;
                color: #f8fafc;
                font-size: 1rem;
                transition: all 0.3s ease;
                font-family: inherit;
            }
            
            input:focus,
            textarea:focus,
            select:focus {
                outline: none;
                border-color: #3b82f6;
                box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
            }
            
            input::placeholder,
            textarea::placeholder {
                color: #94a3b8;
            }
            
            label {
                display: block;
                margin-bottom: 0.5rem;
                color: #f8fafc;
                font-weight: 500;
            }
            
            .form-group {
                margin-bottom: 1.5rem;
            }
            
            .form-label {
                display: block;
                margin-bottom: 0.5rem;
                color: #f8fafc;
                font-weight: 500;
            }
            
            .form-input,
            .form-select,
            .form-textarea {
                width: 100%;
                padding: 0.75rem 1rem;
                border: 1px solid #334155;
                border-radius: 8px;
                background: #1e293b;
                color: #f8fafc;
                font-size: 1rem;
                transition: all 0.3s ease;
            }
            
            .form-textarea {
                resize: vertical;
                min-height: 100px;
            }
            
            .form-error {
                margin-top: 0.5rem;
                color: #ef4444;
                font-size: 0.875rem;
            }
            
            /* === BUTTONS === */
            button,
            .btn,
            input[type="submit"],
            input[type="button"] {
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                padding: 0.75rem 1.5rem;
                border: none;
                border-radius: 8px;
                font-size: 0.9rem;
                font-weight: 500;
                cursor: pointer;
                text-decoration: none;
                transition: all 0.3s ease;
                white-space: nowrap;
                font-family: inherit;
            }
            
            .btn-primary,
            input[type="submit"] {
                background: #3b82f6;
                color: white;
            }
            
            .btn-primary:hover,
            input[type="submit"]:hover {
                background: #2563eb;
                transform: translateY(-1px);
            }
            
            .btn-success {
                background: #10b981;
                color: white;
            }
            
            .btn-success:hover {
                background: #059669;
                transform: translateY(-1px);
            }
            
            .btn-warning {
                background: #f59e0b;
                color: #1f2937;
            }
            
            .btn-warning:hover {
                background: #d97706;
                transform: translateY(-1px);
            }
            
            .btn-danger {
                background: #ef4444;
                color: white;
            }
            
            .btn-danger:hover {
                background: #dc2626;
                transform: translateY(-1px);
            }
            
            .btn-secondary {
                background: #1e293b;
                color: #f8fafc;
                border: 1px solid #334155;
            }
            
            .btn-secondary:hover {
                background: #334155;
                transform: translateY(-1px);
            }
            
            button:disabled,
            .btn:disabled {
                opacity: 0.5;
                cursor: not-allowed;
                transform: none !important;
            }
            
            /* === TABLES === */
            table {
                width: 100%;
                border-collapse: collapse;
                background: #1e293b;
                border-radius: 8px;
                overflow: hidden;
            }
            
            .table-container {
                overflow-x: auto;
                border-radius: 8px;
                border: 1px solid #334155;
            }
            
            table th,
            table td {
                padding: 1rem;
                text-align: left;
                border-bottom: 1px solid #334155;
            }
            
            thead,
            table thead {
                background: #1e293b;
            }
            
            th,
            table th {
                background: #1e293b;
                font-weight: 600;
                color: #f8fafc;
            }
            
            td,
            table td {
                color: #f8fafc;
            }
            
            tbody tr:hover,
            table tbody tr:hover {
                background: #1e293b;
            }
            
            /* === CARDS & TILES === */
            .card,
            .tile {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 1.5rem;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                transition: all 0.3s ease;
                margin-bottom: 1.5rem;
            }
            
            .card:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }
            
            .card-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1rem;
                padding-bottom: 1rem;
                border-bottom: 1px solid #334155;
            }
            
            .card-title {
                font-size: 1.25rem;
                font-weight: 600;
                color: #f8fafc;
            }
            
            .card-content {
                color: #f8fafc;
            }
            
            /* === DASHBOARD GRID === */
            .grid {
                display: grid;
                gap: 1.5rem;
            }
            
            .grid-cols-1 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
            .grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
            .grid-cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
            
            @media (max-width: 768px) {
                .grid-cols-2, .grid-cols-3, .grid-cols-4 {
                    grid-template-columns: 1fr;
                }
            }
            
            /* === STAT CARDS === */
            .stat-card {
                display: flex;
                align-items: center;
                gap: 0.85rem;
                padding: 1.275rem;
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 13.6px;
                transition: all 0.3s ease;
                position: relative;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3), 0 1px 3px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1), inset 0 -1px 0 rgba(0, 0, 0, 0.4);
                background: linear-gradient(145deg, rgba(255, 255, 255, 0.05) 0%, transparent 50%, rgba(0, 0, 0, 0.1) 100%), #1e293b;
            }
            
            .stat-card:hover {
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3), 0 4px 10px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1), inset 0 -1px 0 rgba(0, 0, 0, 0.4);
            }
            
            .stat-icon {
                width: 40.8px;
                height: 40.8px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 10.2px;
                font-size: 1.275rem;
            }
            
            .stat-icon.primary {
                background: rgba(59, 130, 246, 0.2);
                color: #3b82f6;
            }
            
            .stat-icon.success {
                background: rgba(16, 185, 129, 0.2);
                color: #10b981;
            }
            
            .stat-icon.warning {
                background: rgba(245, 158, 11, 0.2);
                color: #f59e0b;
            }
            
            .stat-icon.danger {
                background: rgba(239, 68, 68, 0.2);
                color: #ef4444;
            }
            
            .stat-content {
                flex: 1;
            }
            
            .stat-value {
                font-size: 1.275rem;
                font-weight: 700;
                color: #f8fafc;
            }
            
            .stat-label {
                color: #cbd5e1;
                font-size: 0.744rem;
                margin-top: 1.7px;
            }
            
            /* === BADGES === */
            .badge {
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                padding: 0.25rem 0.75rem;
                border-radius: 9999px;
                font-size: 0.75rem;
                font-weight: 500;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            .badge-success {
                background: rgba(16, 185, 129, 0.2);
                color: #10b981;
            }
            
            .badge-warning {
                background: rgba(245, 158, 11, 0.2);
                color: #f59e0b;
            }
            
            .badge-danger {
                background: rgba(239, 68, 68, 0.2);
                color: #ef4444;
            }
            
            .badge-info {
                background: rgba(59, 130, 246, 0.2);
                color: #3b82f6;
            }
            
            .badge-secondary {
                background: #1e293b;
                color: #cbd5e1;
            }
            
            /* SIGMA Rule Badges */
            .badge-critical {
                background: rgba(211, 47, 47, 0.2);
                color: #f44336;
            }
            
            .badge-high {
                background: rgba(244, 67, 54, 0.2);
                color: #ff5722;
            }
            
            .badge-medium {
                background: rgba(255, 152, 0, 0.2);
                color: #ff9800;
            }
            
            .badge-low {
                background: rgba(33, 150, 243, 0.2);
                color: #2196f3;
            }
            
            /* === ALERTS === */
            .alert {
                padding: 1rem 1.5rem;
                border-radius: 8px;
                margin-bottom: 1rem;
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 1rem;
            }
            
            .alert-success {
                background: rgba(16, 185, 129, 0.1);
                border: 1px solid #10b981;
                color: #10b981;
            }
            
            .alert-error {
                background: rgba(239, 68, 68, 0.1);
                border: 1px solid #ef4444;
                color: #ef4444;
            }
            
            .alert-warning {
                background: rgba(245, 158, 11, 0.1);
                border: 1px solid #f59e0b;
                color: #f59e0b;
            }
            
            .alert-info {
                background: rgba(59, 130, 246, 0.1);
                border: 1px solid #3b82f6;
                color: #3b82f6;
            }
            
            .alert-close {
                background: none;
                border: none;
                color: inherit;
                cursor: pointer;
                padding: 0;
            }
            
            /* === LOGIN PAGE === */
            .login-container,
            .container {
                max-width: 400px;
                margin: 100px auto;
                padding: 40px;
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 8px;
            }
            
            .login-container .logo,
            .container .logo {
                text-align: center;
                font-size: 2.5em;
                margin-bottom: 30px;
            }
            
            .login-container .logo .case,
            .container .logo .case {
                color: #10b981;
            }
            
            .login-container .logo .scope,
            .container .logo .scope {
                color: #f8fafc;
            }
            
            .login-container form,
            .container form {
                margin-top: 25px;
            }
            
            .login-container input,
            .container input {
                margin-bottom: 15px;
            }
            
            .login-container button,
            .container button {
                width: 100%;
                background: #10b981;
                border-color: #10b981;
                color: white;
                padding: 12px;
                font-size: 16px;
            }
            
            .login-container button:hover,
            .container button:hover {
                background: #059669;
                border-color: #059669;
            }
            
            .login-container .version,
            .container .version {
                text-align: center;
                margin-top: 20px;
                font-size: 0.85em;
                color: #94a3b8;
            }
            
            /* === UPLOAD PAGE === */
            .upload-area {
                border: 2px dashed #334155;
                border-radius: 12px;
                padding: 3rem;
                text-align: center;
                transition: all 0.3s ease;
                cursor: pointer;
                -webkit-user-select: none;
                -moz-user-select: none;
                -ms-user-select: none;
                user-select: none;
            }
            
            .upload-area:hover,
            .upload-area.dragover {
                border-color: #3b82f6;
                background: rgba(59, 130, 246, 0.05);
            }
            
            .upload-icon {
                font-size: 3rem;
                color: #cbd5e1;
                margin-bottom: 1rem;
            }
            
            .upload-text {
                color: #f8fafc;
                font-size: 1.1rem;
                margin-bottom: 0.5rem;
            }
            
            .upload-subtext {
                color: #cbd5e1;
                font-size: 0.9rem;
            }
            
            /* === FILE LIST === */
            .file-item {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                margin-bottom: 0.5rem;
            }
            
            .file-main {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 1rem;
                min-height: 80px;
                gap: 1rem;
            }
            
            .file-main .file-info {
                flex: 1;
                min-width: 0;
            }
            
            .file-main .file-status {
                flex-shrink: 0;
                white-space: nowrap;
            }
            
            .file-main .file-stats {
                flex-shrink: 0;
                display: flex;
                gap: 0.5rem;
                align-items: center;
            }
            
            .file-main .file-actions {
                flex-shrink: 0;
                display: flex;
                gap: 0.5rem;
                align-items: center;
                justify-content: flex-end;
                margin-left: auto;
            }
            
            .file-name {
                font-weight: 500;
                color: #f8fafc;
            }
            
            .file-meta {
                font-size: 0.8rem;
                color: #cbd5e1;
                margin-top: 0.25rem;
            }
            
            .action-btn {
                background: none;
                border: none;
                color: #cbd5e1;
                cursor: pointer;
                padding: 0.5rem;
                border-radius: 6px;
                transition: all 0.3s ease;
                width: 32px;
                height: 32px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .action-btn:hover {
                background: #1e293b;
                color: #f8fafc;
            }
            
            /* === PROGRESS BARS === */
            .progress {
                width: 100%;
                height: 8px;
                background: #334155;
                border-radius: 4px;
                overflow: hidden;
            }
            
            .progress-bar {
                height: 100%;
                background: #3b82f6;
                transition: width 0.3s ease;
            }
            
            .progress-bar.success {
                background: #10b981;
            }
            
            .progress-bar.warning {
                background: #f59e0b;
            }
            
            .progress-bar.danger {
                background: #ef4444;
            }
            
            /* === UTILITY CLASSES === */
            .text-center { text-align: center; }
            .text-left { text-align: left; }
            .text-right { text-align: right; }
            
            .mt-1 { margin-top: 0.25rem; }
            .mt-2 { margin-top: 0.5rem; }
            .mt-3 { margin-top: 0.75rem; }
            .mt-4 { margin-top: 1rem; }
            
            .mb-1 { margin-bottom: 0.25rem; }
            .mb-2 { margin-bottom: 0.5rem; }
            .mb-3 { margin-bottom: 0.75rem; }
            .mb-4 { margin-bottom: 1rem; }
            
            .flex { display: flex; }
            .items-center { align-items: center; }
            .justify-between { justify-content: space-between; }
            .gap-2 { gap: 0.5rem; }
            .gap-4 { gap: 1rem; }
            
            .hidden { display: none; }
            
            /* === SCROLLBAR === */
            ::-webkit-scrollbar {
                width: 10px;
                height: 10px;
            }
            
            ::-webkit-scrollbar-track {
                background: #0f172a;
            }
            
            ::-webkit-scrollbar-thumb {
                background: #334155;
                border-radius: 5px;
            }
            
            ::-webkit-scrollbar-thumb:hover {
                background: #475569;
            }
            
            /* === RESPONSIVE === */
            @media (max-width: 1024px) {
                .sidebar {
                    width: 240px;
                }
            }
            
            @media (max-width: 768px) {
                body {
                    flex-direction: column;
                }
                
                .sidebar {
                    width: 100%;
                    max-height: 200px;
                    border-right: none;
                    border-bottom: 1px solid #334155;
                }
                
                .header {
                    padding: 0.75rem 1rem;
                }
                
                .content {
                    padding: 1rem;
                }
            }
        </style>
    '''
