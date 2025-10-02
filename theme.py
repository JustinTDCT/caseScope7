"""
Dark Theme for caseScope 7 - Hybrid approach
Uses v7.0 colors and styling but adapted for main.py HTML structure
"""

def get_theme_css():
    """
    Hybrid theme: v7.0 colors + main.py HTML structure
    
    main.py structure:
    <body>
      <div class="sidebar">...</div>
      <div class="main-content">
        <div class="header">...</div>
        <div class="content">...</div>
      </div>
      <div class="footer">...</div>  <!-- OUTSIDE main-content -->
    </body>
    """
    return '''
        <style>
            /* caseScope 7 - v7.0 Colors + main.py Structure */
            
            /* === RESET & BASE === */
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            html, body {
                height: 100%;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                background: #0f172a;
                color: #f8fafc;
                line-height: 1.6;
            }
            
            body { 
                display: flex; 
                flex-wrap: wrap;
                min-height: 100vh; 
            }
            
            /* === SIDEBAR === */
            .sidebar { 
                width: 280px; 
                background: #0f172a;
                border-right: 1px solid #334155;
                padding: 1rem;
                overflow-y: auto;
                flex-shrink: 0;
                box-shadow: inset -1px 0 0 rgba(255, 255, 255, 0.1), 2px 0 4px rgba(0, 0, 0, 0.3);
                height: 100vh;
                position: sticky;
                top: 0;
            }
            
            .sidebar-logo {
                text-align: center;
                font-size: 1.8rem;
                font-weight: bold;
                padding-bottom: 1rem;
                margin-bottom: 1.5rem;
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
                margin: 1.5rem 0 0.5rem 0;
            }
            
            .menu-item { 
                display: block; 
                padding: 0.75rem 1rem;
                color: #f8fafc;
                text-decoration: none; 
                border-radius: 8px;
                transition: all 0.3s ease;
                font-size: 0.9rem;
                margin: 0.25rem 0;
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
            
            /* === MAIN CONTENT WRAPPER === */
            .main-content {
                flex: 1;
                display: flex;
                flex-direction: column;
                min-width: 0;
                max-height: 100vh;
                overflow: hidden;
            }
            
            /* === HEADER === */
            .header {
                background: #1e293b;
                background: linear-gradient(180deg, rgba(255, 255, 255, 0.03) 0%, #1e293b 50%, rgba(0, 0, 0, 0.05) 100%);
                border-bottom: 1px solid #334155;
                padding: 1rem 2rem;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1), inset 0 -1px 0 rgba(0, 0, 0, 0.4);
                flex-shrink: 0;
                display: flex;
                justify-content: flex-end;
                align-items: center;
            }
            
            .header h1 {
                font-size: 1.8rem;
                font-weight: 400;
                color: #f8fafc;
                margin: 0;
                padding: 0;
                border: none;
            }
            
            .user-info {
                display: flex;
                align-items: center;
                gap: 1rem;
                color: #cbd5e1;
                font-size: 0.9rem;
                margin-left: auto;
            }
            
            .logout-btn {
                background: #ef4444;
                color: white;
                padding: 0.5rem 1rem;
                border-radius: 6px;
                text-decoration: none;
                font-size: 0.875rem;
                font-weight: 500;
                transition: all 0.2s ease;
                border: 1px solid #ef4444;
                cursor: pointer;
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                line-height: 1;
            }
            
            .logout-btn:hover {
                background: #dc2626;
                border-color: #dc2626;
                transform: translateY(-1px);
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
            }
            
            .logout-btn:active {
                transform: translateY(0);
                box-shadow: none;
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
                width: 100%;
                background: #1e293b;
                border-top: 1px solid #334155;
                padding: 1rem 2rem;
                color: #cbd5e1;
                font-size: 0.875rem;
                text-align: right;
                flex-shrink: 0;
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
            
            p {
                line-height: 1.6;
                color: #cbd5e1;
                margin-bottom: 1rem;
            }
            
            strong {
                color: #f8fafc;
                font-weight: 600;
            }
            
            /* === TILES === */
            .tiles {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 1.5rem;
                margin-bottom: 2rem;
            }
            
            .tile {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 1.5rem;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3), 0 1px 3px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1), inset 0 -1px 0 rgba(0, 0, 0, 0.4);
                background: linear-gradient(145deg, rgba(255, 255, 255, 0.05) 0%, transparent 50%, rgba(0, 0, 0, 0.1) 100%), #1e293b;
                transition: all 0.3s ease;
            }
            
            .tile:hover {
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3), 0 4px 10px rgba(0, 0, 0, 0.3);
            }
            
            .tile h3 {
                margin: 0 0 1rem 0;
                color: #cbd5e1;
                font-size: 1rem;
                font-weight: 600;
                padding-bottom: 0.5rem;
                border-bottom: 1px solid #334155;
            }
            
            .tile p {
                margin-bottom: 0.75rem;
                color: #cbd5e1;
                line-height: 1.6;
            }
            
            .tile p:last-child {
                margin-bottom: 0;
            }
            
            .tile a {
                color: #10b981;
                text-decoration: none;
                transition: color 0.2s;
            }
            
            .tile a:hover {
                color: #059669;
                text-decoration: none;
            }
            
            /* === STATUS INDICATORS === */
            .status {
                display: inline-block;
                padding: 0.25rem 0.5rem;
                border-radius: 4px;
                font-size: 0.85rem;
                font-weight: 600;
            }
            
            .status.operational {
                background: rgba(16, 185, 129, 0.2);
                color: #10b981;
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
            
            /* === BUTTONS === */
            button,
            .btn,
            input[type="submit"],
            input[type="button"],
            a.btn {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 0.5rem;
                padding: 0.5rem 1rem;
                border: none;
                border-radius: 6px;
                font-size: 0.875rem;
                font-weight: 500;
                cursor: pointer;
                text-decoration: none;
                transition: all 0.2s ease;
                font-family: inherit;
                background: #1e293b;
                color: #f8fafc;
                border: 1px solid #334155;
                line-height: 1;
            }
            
            button:hover,
            .btn:hover,
            input[type="submit"]:hover,
            input[type="button"]:hover,
            a.btn:hover {
                background: #334155;
                border-color: #475569;
                transform: translateY(-1px);
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
            }
            
            button:active,
            .btn:active,
            input[type="submit"]:active,
            a.btn:active {
                transform: translateY(0);
                box-shadow: none;
            }
            
            button:disabled,
            .btn:disabled,
            a.btn:disabled {
                opacity: 0.5;
                cursor: not-allowed;
                transform: none !important;
            }
            
            /* Button variants */
            .btn-primary,
            button[type="submit"]:not(.btn-danger):not(.btn-warning):not(.btn-success),
            input[type="submit"] {
                background: #3b82f6;
                border-color: #3b82f6;
                color: white;
            }
            
            .btn-primary:hover,
            button[type="submit"]:not(.btn-danger):not(.btn-warning):not(.btn-success):hover,
            input[type="submit"]:hover {
                background: #2563eb;
                border-color: #2563eb;
            }
            
            .btn-success {
                background: #10b981;
                border-color: #10b981;
                color: white;
            }
            
            .btn-success:hover {
                background: #059669;
                border-color: #059669;
            }
            
            .btn-danger {
                background: #ef4444;
                border-color: #ef4444;
                color: white;
            }
            
            .btn-danger:hover {
                background: #dc2626;
                border-color: #dc2626;
            }
            
            .btn-warning {
                background: #f59e0b;
                border-color: #f59e0b;
                color: #1f2937;
            }
            
            .btn-warning:hover {
                background: #d97706;
                border-color: #d97706;
            }
            
            .btn-secondary {
                background: #1e293b;
                border-color: #334155;
                color: #cbd5e1;
            }
            
            .btn-secondary:hover {
                background: #334155;
                border-color: #475569;
            }
            
            /* Small buttons */
            .btn-sm,
            button.btn-sm {
                padding: 0.375rem 0.75rem;
                font-size: 0.8rem;
            }
            
            /* Link buttons - styled as links */
            a:not(.btn):not(.menu-item):not(.logout-btn) {
                color: #3b82f6;
                text-decoration: none;
                transition: color 0.2s;
            }
            
            a:not(.btn):not(.menu-item):not(.logout-btn):hover {
                color: #2563eb;
                text-decoration: none;
            }
            
            /* === TABLES === */
            table {
                width: 100%;
                border-collapse: collapse;
                background: #1e293b;
                border-radius: 8px;
                overflow: hidden;
            }
            
            thead {
                background: #1e293b;
            }
            
            th {
                padding: 1rem;
                text-align: left;
                font-weight: 600;
                color: #f8fafc;
                border-bottom: 1px solid #334155;
            }
            
            td {
                padding: 1rem;
                color: #f8fafc;
                border-bottom: 1px solid #334155;
            }
            
            tbody tr:hover {
                background: rgba(59, 130, 246, 0.1);
            }
            
            /* === CARDS === */
            .card {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 1.5rem;
                margin-bottom: 1.5rem;
            }
            
            .card h3 {
                margin-top: 0;
            }
            
            /* === BADGES === */
            .badge {
                display: inline-block;
                padding: 0.25rem 0.75rem;
                border-radius: 9999px;
                font-size: 0.75rem;
                font-weight: 500;
                text-transform: uppercase;
            }
            
            .badge-success {
                background: rgba(16, 185, 129, 0.2);
                color: #10b981;
            }
            
            .badge-danger {
                background: rgba(239, 68, 68, 0.2);
                color: #ef4444;
            }
            
            .badge-warning {
                background: rgba(245, 158, 11, 0.2);
                color: #f59e0b;
            }
            
            .badge-info {
                background: rgba(59, 130, 246, 0.2);
                color: #3b82f6;
            }
            
            /* === ALERTS === */
            .alert {
                padding: 1rem 1.5rem;
                border-radius: 8px;
                margin-bottom: 1rem;
                border-left: 4px solid;
            }
            
            .alert-success {
                background: rgba(16, 185, 129, 0.1);
                border-color: #10b981;
                color: #10b981;
            }
            
            .alert-error {
                background: rgba(239, 68, 68, 0.1);
                border-color: #ef4444;
                color: #ef4444;
            }
            
            .alert-warning {
                background: rgba(245, 158, 11, 0.1);
                border-color: #f59e0b;
                color: #f59e0b;
            }
            
            .alert-info {
                background: rgba(59, 130, 246, 0.1);
                border-color: #3b82f6;
                color: #3b82f6;
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
            
            .login-container button,
            .container button {
                width: 100%;
                padding: 12px;
                font-size: 16px;
            }
            
            /* === UPLOAD PAGE === */
            .upload-page-container {
                max-width: 1000px;
                margin: 0 auto;
            }
            
            .upload-info-card {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 1.5rem;
                margin-bottom: 2rem;
            }
            
            .upload-info-card h3 {
                color: #f8fafc;
                margin-top: 0;
                margin-bottom: 1rem;
                font-size: 1.1rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }
            
            .upload-info-card ul {
                list-style: none;
                padding: 0;
                margin: 0;
            }
            
            .upload-info-card li {
                padding: 0.5rem 0;
                color: #cbd5e1;
                font-size: 0.95rem;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }
            
            .upload-info-card li:before {
                content: "✓";
                color: #10b981;
                font-weight: bold;
                font-size: 1.1rem;
            }
            
            .upload-dropzone {
                background: #1e293b;
                border: 3px dashed #475569;
                border-radius: 12px;
                padding: 4rem 2rem;
                text-align: center;
                cursor: pointer;
                transition: all 0.3s ease;
                margin-bottom: 2rem;
                min-height: 300px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .upload-dropzone:hover {
                border-color: #3b82f6;
                background: rgba(59, 130, 246, 0.05);
            }
            
            .upload-dropzone.dragover {
                border-color: #10b981;
                border-style: solid;
                background: rgba(16, 185, 129, 0.1);
                transform: scale(1.02);
            }
            
            .upload-dropzone-content {
                pointer-events: none;
            }
            
            .upload-icon {
                font-size: 5rem;
                margin-bottom: 1.5rem;
                opacity: 0.7;
            }
            
            .upload-primary-text {
                font-size: 1.3rem;
                color: #f8fafc;
                font-weight: 500;
                margin-bottom: 0.75rem;
            }
            
            .upload-secondary-text {
                font-size: 1rem;
                color: #94a3b8;
            }
            
            .file-list {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 1.5rem;
                margin-bottom: 2rem;
            }
            
            .file-list h3 {
                color: #f8fafc;
                margin-top: 0;
                margin-bottom: 1.5rem;
                font-size: 1.1rem;
            }
            
            .file-item {
                display: flex;
                align-items: center;
                gap: 1rem;
                padding: 1rem;
                background: #0f172a;
                border: 1px solid #334155;
                border-radius: 8px;
                margin-bottom: 0.75rem;
                transition: all 0.2s ease;
            }
            
            .file-item:hover {
                border-color: #475569;
                background: #1e293b;
            }
            
            .file-item-error {
                display: flex;
                align-items: center;
                gap: 1rem;
                padding: 1rem;
                background: rgba(239, 68, 68, 0.1);
                border: 1px solid #ef4444;
                border-radius: 8px;
                margin-bottom: 0.75rem;
            }
            
            .file-item-icon {
                font-size: 2rem;
                opacity: 0.7;
            }
            
            .file-item-details {
                flex: 1;
                min-width: 0;
            }
            
            .file-item-name {
                color: #f8fafc;
                font-weight: 500;
                font-size: 1rem;
                margin-bottom: 0.25rem;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            
            .file-item-size {
                color: #94a3b8;
                font-size: 0.9rem;
            }
            
            .file-item-remove {
                width: 32px;
                height: 32px;
                display: flex;
                align-items: center;
                justify-content: center;
                background: #334155;
                border-radius: 6px;
                color: #f8fafc;
                cursor: pointer;
                transition: all 0.2s ease;
                font-size: 1.2rem;
                font-weight: bold;
            }
            
            .file-item-remove:hover {
                background: #ef4444;
                transform: scale(1.1);
            }
            
            .file-list-total {
                padding: 1rem;
                background: rgba(59, 130, 246, 0.1);
                border: 1px solid #3b82f6;
                border-radius: 8px;
                color: #3b82f6;
                font-weight: 500;
                text-align: center;
                margin-top: 1rem;
            }
            
            .upload-actions {
                display: flex;
                gap: 1rem;
                justify-content: center;
                align-items: center;
                flex-wrap: wrap;
            }
            
            .upload-actions .btn {
                min-width: 150px;
            }
            
            /* === SEARCH PAGE === */
            .stats-bar {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 1rem 1.5rem;
                margin-bottom: 1.5rem;
                color: #cbd5e1;
            }
            
            .search-box {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 1.5rem;
                margin-bottom: 1.5rem;
            }
            
            .search-input {
                width: 100%;
                min-width: 400px;
                padding: 12px 16px;
                font-size: 1rem;
                margin-bottom: 1rem;
            }
            
            .search-actions {
                display: flex;
                align-items: center;
                gap: 1rem;
                flex-wrap: wrap;
            }
            
            .help-box {
                background: #0f172a;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 1.5rem;
                margin-top: 1rem;
                display: none;
            }
            
            .help-box.show {
                display: block;
            }
            
            .help-box h4 {
                color: #f8fafc;
                margin-top: 0;
                margin-bottom: 1rem;
            }
            
            .help-box ul {
                list-style: none;
                padding: 0;
                margin: 0;
            }
            
            .help-box li {
                padding: 0.5rem 0;
                color: #cbd5e1;
                border-bottom: 1px solid #334155;
            }
            
            .help-box li:last-child {
                border-bottom: none;
            }
            
            .help-box code {
                background: #1e293b;
                color: #10b981;
                padding: 2px 6px;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
            }
            
            .field-tag {
                color: #10b981;
                cursor: pointer;
                padding: 2px 6px;
                border-radius: 4px;
                transition: all 0.2s;
            }
            
            .field-tag:hover {
                background: rgba(16, 185, 129, 0.2);
            }
            
            .result-row {
                cursor: pointer;
            }
            
            .result-row:hover {
                background: rgba(59, 130, 246, 0.1);
            }
            
            .details-row {
                background: #0f172a;
            }
            
            .event-details {
                padding: 1.5rem;
            }
            
            .event-details h4 {
                margin-top: 0;
                color: #f8fafc;
            }
            
            .event-details pre {
                background: #1e293b;
                padding: 1rem;
                border-radius: 6px;
                overflow-x: auto;
                color: #cbd5e1;
                font-size: 0.9rem;
                line-height: 1.5;
            }
            
            .pagination {
                display: flex;
                justify-content: center;
                align-items: center;
                gap: 1rem;
                margin-top: 2rem;
                padding: 1rem;
            }
            
            .page-btn {
                padding: 0.5rem 1rem;
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                color: #f8fafc;
                text-decoration: none;
                transition: all 0.2s;
            }
            
            .page-btn:hover {
                background: #334155;
                border-color: #475569;
            }
            
            .page-info {
                color: #cbd5e1;
                font-size: 0.95rem;
            }
            
            /* === SIGMA VIOLATIONS PAGE === */
            .stats-bar {
                display: flex;
                gap: 1.5rem;
                margin-bottom: 2rem;
                flex-wrap: wrap;
            }
            
            .stat-item {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 1.5rem;
                min-width: 150px;
                text-align: center;
                flex: 1;
            }
            
            .stat-value {
                font-size: 2.5rem;
                font-weight: bold;
                color: #f8fafc;
                margin-bottom: 0.5rem;
            }
            
            .stat-value.critical {
                color: #ef4444;
            }
            
            .stat-value.high {
                color: #f59e0b;
            }
            
            .stat-value.medium {
                color: #3b82f6;
            }
            
            .stat-value.low {
                color: #10b981;
            }
            
            .stat-label {
                font-size: 0.9rem;
                color: #cbd5e1;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            .filter-bar {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 1rem 1.5rem;
                margin-bottom: 1.5rem;
                display: flex;
                align-items: center;
                gap: 1rem;
                flex-wrap: wrap;
            }
            
            .filter-bar strong {
                color: #f8fafc;
            }
            
            .filter-bar select {
                min-width: 200px;
            }
            
            .severity-badge {
                display: inline-block;
                padding: 0.25rem 0.75rem;
                border-radius: 4px;
                font-size: 0.75rem;
                font-weight: bold;
                color: white;
                text-transform: uppercase;
            }
            
            .review-badge {
                display: inline-block;
                padding: 0.25rem 0.75rem;
                border-radius: 4px;
                font-size: 0.85rem;
                font-weight: 500;
            }
            
            .review-badge.review-reviewed {
                background: rgba(16, 185, 129, 0.2);
                color: #10b981;
            }
            
            .review-badge.review-pending {
                background: rgba(245, 158, 11, 0.2);
                color: #f59e0b;
            }
            
            .actions-cell {
                display: flex;
                gap: 0.5rem;
                justify-content: flex-end;
            }
            
            .btn-action {
                padding: 0.375rem 0.75rem;
                font-size: 0.85rem;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                transition: all 0.2s;
            }
            
            .btn-view {
                background: #3b82f6;
                color: white;
            }
            
            .btn-view:hover {
                background: #2563eb;
            }
            
            .btn-review {
                background: #10b981;
                color: white;
            }
            
            .btn-review:hover {
                background: #059669;
            }
            
            .btn-edit {
                background: #3b82f6;
                color: white;
            }
            
            .btn-edit:hover {
                background: #2563eb;
            }
            
            .btn-delete {
                background: #ef4444;
                color: white;
            }
            
            .btn-delete:hover {
                background: #dc2626;
            }
            
            .violation-details {
                background: #0f172a;
            }
            
            .violation-detail-panel {
                padding: 1.5rem;
            }
            
            .detail-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 1rem;
                margin-bottom: 1.5rem;
            }
            
            .detail-item {
                background: #1e293b;
                padding: 1rem;
                border-radius: 6px;
                border: 1px solid #334155;
            }
            
            .detail-item strong {
                color: #f8fafc;
                display: block;
                margin-bottom: 0.5rem;
            }
            
            .event-json {
                background: #1e293b;
                padding: 1rem;
                border-radius: 6px;
                overflow-x: auto;
                color: #cbd5e1;
                font-size: 0.9rem;
                line-height: 1.5;
            }
            
            /* === SIGMA RULES PAGE === */
            .rule-row {
                cursor: pointer;
            }
            
            .rule-row:hover {
                background: rgba(59, 130, 246, 0.05);
            }
            
            .rule-title {
                font-weight: 500;
                color: #f8fafc;
                margin-bottom: 0.25rem;
            }
            
            .rule-description {
                font-size: 0.9rem;
                color: #94a3b8;
            }
            
            .tag {
                display: inline-block;
                padding: 0.25rem 0.5rem;
                background: rgba(59, 130, 246, 0.2);
                color: #3b82f6;
                border-radius: 4px;
                font-size: 0.75rem;
                margin-right: 0.25rem;
                margin-bottom: 0.25rem;
            }
            
            .builtin-badge {
                display: inline-block;
                padding: 0.25rem 0.5rem;
                background: rgba(16, 185, 129, 0.2);
                color: #10b981;
                border-radius: 4px;
                font-size: 0.75rem;
                margin-left: 0.5rem;
            }
            
            .user-badge {
                display: inline-block;
                padding: 0.25rem 0.5rem;
                background: rgba(245, 158, 11, 0.2);
                color: #f59e0b;
                border-radius: 4px;
                font-size: 0.75rem;
                margin-left: 0.5rem;
            }
            
            /* === USER MANAGEMENT PAGE === */
            .role-badge {
                display: inline-block;
                padding: 0.25rem 0.75rem;
                border-radius: 4px;
                font-size: 0.85rem;
                font-weight: 500;
                color: white;
            }
            
            .status-badge {
                display: inline-block;
                padding: 0.25rem 0.75rem;
                border-radius: 4px;
                font-size: 0.85rem;
                font-weight: 500;
            }
            
            .status-badge.status-active {
                background: rgba(16, 185, 129, 0.2);
                color: #10b981;
            }
            
            .status-badge.status-inactive {
                background: rgba(239, 68, 68, 0.2);
                color: #ef4444;
            }
            
            /* Modal styles */
            .modal {
                display: none;
                position: fixed;
                z-index: 1000;
                left: 0;
                top: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.7);
                align-items: center;
                justify-content: center;
            }
            
            .modal.show {
                display: flex;
            }
            
            .modal-content {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 2rem;
                max-width: 500px;
                width: 90%;
                max-height: 90vh;
                overflow-y: auto;
            }
            
            .modal-content h2 {
                margin-top: 0;
                color: #f8fafc;
                margin-bottom: 1.5rem;
            }
            
            /* Flash messages */
            .flash-message {
                display: flex;
                align-items: center;
                gap: 1rem;
                padding: 1rem 1.5rem;
                border-radius: 8px;
                margin-bottom: 1rem;
                border-left: 4px solid;
            }
            
            .flash-message.flash-success {
                background: rgba(16, 185, 129, 0.1);
                border-color: #10b981;
                color: #10b981;
            }
            
            .flash-message.flash-error {
                background: rgba(239, 68, 68, 0.1);
                border-color: #ef4444;
                color: #ef4444;
            }
            
            .flash-message.flash-warning {
                background: rgba(245, 158, 11, 0.1);
                border-color: #f59e0b;
                color: #f59e0b;
            }
            
            .flash-message.flash-info {
                background: rgba(59, 130, 246, 0.1);
                border-color: #3b82f6;
                color: #3b82f6;
            }
            
            .flash-icon {
                font-size: 1.5rem;
            }
            
            .flash-text {
                flex: 1;
            }
            
            .flash-close {
                background: none;
                border: none;
                color: inherit;
                font-size: 1.5rem;
                cursor: pointer;
                padding: 0;
                width: 24px;
                height: 24px;
                display: flex;
                align-items: center;
                justify-content: center;
                opacity: 0.7;
            }
            
            .flash-close:hover {
                opacity: 1;
            }
            
            /* === UTILITY CLASSES === */
            .text-center { text-align: center; }
            .text-right { text-align: right; }
            .mt-2 { margin-top: 1rem; }
            .mb-2 { margin-bottom: 1rem; }
            
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
            @media (max-width: 768px) {
                body {
                    flex-direction: column;
                }
                
                .sidebar {
                    width: 100%;
                    height: auto;
                    max-height: 300px;
                    border-right: none;
                    border-bottom: 1px solid #334155;
                    position: relative;
                }
                
                .main-content {
                    max-height: none;
                }
                
                .content {
                    padding: 1rem;
                }
            }
        </style>
    '''
