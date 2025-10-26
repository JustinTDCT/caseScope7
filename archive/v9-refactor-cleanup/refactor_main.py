#!/usr/bin/env python3
"""
One-shot refactoring script to modularize main.py
This script removes model definitions and replaces them with imports
"""

import re

def refactor_main():
    print("[Refactor] Reading main.py...")
    with open('main.py', 'r') as f:
        content = f.read()
    
    original_lines = len(content.split('\n'))
    print(f"[Refactor] Original file: {original_lines} lines")
    
    # Find where models start and end
    models_start = content.find('class User(UserMixin, db.Model):')
    models_end = content.find('@login_manager.user_loader')
    
    if models_start == -1 or models_end == -1:
        print("[Refactor] ERROR: Could not find model boundaries")
        return False
    
    print(f"[Refactor] Models section: lines {content[:models_start].count(chr(10))} to {content[:models_end].count(chr(10))}")
    
    # Find where log_audit function is
    log_audit_start = content.find('# Audit logging helper\ndef log_audit(')
    log_audit_end = content.find('\n\n# ZIP Extraction Helper Function', log_audit_start)
    
    if log_audit_start == -1 or log_audit_end == -1:
        print("[Refactor] ERROR: Could not find log_audit function")
        return False
    
    # Extract everything before models
    before_models = content[:models_start]
    
    # Extract everything between models_end and log_audit
    between_models_and_audit = content[models_end:log_audit_start]
    
    # Extract everything after log_audit
    after_audit = content[log_audit_end:]
    
    # Build new imports section
    new_imports = """
# Import database models
from models import (
    db, User, CaseTemplate, AuditLog, SavedSearch, SearchHistory,
    Case, CaseFile, SigmaRule, SigmaViolation, EventTag, IOC, IOCMatch, SystemSettings
)

# Import utility functions
from utils import log_audit, get_opensearch_client, format_bytes, sanitize_filename, make_index_name
"""
    
    # Modify the Flask app initialization section to use imported db
    # Find and remove "db = SQLAlchemy(app)" line
    before_models = re.sub(
        r'\n# Initialize Extensions\ndb = SQLAlchemy\(app\)\n',
        '\n# Initialize Extensions\ndb.init_app(app)\n',
        before_models
    )
    
    # Remove OpenSearch client initialization (we'll use get_opensearch_client() from utils)
    before_models = re.sub(
        r'\n# OpenSearch Client\nopensearch_client = OpenSearch\([^)]+\)\n',
        '',
        before_models,
        flags=re.DOTALL
    )
    
    # Build new content
    new_content = before_models + new_imports + between_models_and_audit + after_audit
    
    # Update version reference in header
    new_content = new_content.replace('caseScope 7.1.1 - Main Application Entry Point', 'caseScope 9.0.0 - Main Application Entry Point')
    
    # Write new main.py
    print("[Refactor] Writing refactored main.py...")
    with open('main.py', 'w') as f:
        f.write(new_content)
    
    new_lines = len(new_content.split('\n'))
    lines_removed = original_lines - new_lines
    print(f"[Refactor] New file: {new_lines} lines ({lines_removed} lines removed)")
    print(f"[Refactor] ✓ Successfully refactored main.py")
    print(f"[Refactor] Models are now in models.py")
    print(f"[Refactor] Utils are now in utils.py")
    return True

if __name__ == '__main__':
    success = refactor_main()
    exit(0 if success else 1)

