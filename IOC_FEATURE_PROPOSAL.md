# IOC (Indicator of Compromise) Management Feature Proposal
## caseScope v7.14.0

---

## Overview

Add comprehensive IOC management to caseScope for threat hunting across indexed events. Analysts can add, manage, and hunt for indicators within case data.

---

## Database Schema

### New Table: `ioc` (Indicator of Compromise)

```python
class IOC(db.Model):
    """Indicators of Compromise for threat hunting"""
    __tablename__ = 'ioc'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    
    # IOC Details
    ioc_type = db.Column(db.String(50), nullable=False)  # ip, domain, hash_md5, hash_sha1, hash_sha256, email, url, filename, registry_key, user_account, process_name
    ioc_value = db.Column(db.String(500), nullable=False)  # The actual indicator value
    ioc_value_normalized = db.Column(db.String(500))  # Lowercase/normalized for matching
    
    # Context
    description = db.Column(db.Text)  # What this IOC represents
    source = db.Column(db.String(200))  # Where it came from (threat intel feed, manual, etc.)
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    confidence = db.Column(db.String(20), default='medium')  # low, medium, high
    
    # Status
    is_active = db.Column(db.Boolean, default=True)  # Active for hunting
    is_false_positive = db.Column(db.Boolean, default=False)  # Mark as FP
    
    # Threat Hunting
    match_count = db.Column(db.Integer, default=0)  # Number of events matching this IOC
    last_seen = db.Column(db.DateTime)  # Last time this IOC was seen in events
    
    # Metadata
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes = db.Column(db.Text)  # Analyst notes
    
    # Relationships
    case = db.relationship('Case', backref='iocs')
    analyst = db.relationship('User', backref='iocs_added')
    
    # Unique constraint: same IOC value+type per case
    __table_args__ = (
        db.UniqueConstraint('case_id', 'ioc_type', 'ioc_value_normalized', name='unique_case_ioc'),
    )
    
    def __repr__(self):
        return f'<IOC {self.ioc_type}:{self.ioc_value[:30]}>'
```

### New Table: `ioc_match` (IOC Matches in Events)

```python
class IOCMatch(db.Model):
    """Records of IOC matches found in events"""
    __tablename__ = 'ioc_match'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    ioc_id = db.Column(db.Integer, db.ForeignKey('ioc.id'), nullable=False)
    
    # Event Information
    event_id = db.Column(db.String(100), nullable=False)  # OpenSearch doc ID
    index_name = db.Column(db.String(200), nullable=False)
    event_timestamp = db.Column(db.String(100))
    
    # Match Details
    matched_field = db.Column(db.String(200))  # Which field contained the IOC
    matched_value = db.Column(db.Text)  # The actual value that matched
    match_type = db.Column(db.String(50))  # exact, partial, regex
    
    # Metadata
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_reviewed = db.Column(db.Boolean, default=False)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    reviewed_at = db.Column(db.DateTime)
    analyst_notes = db.Column(db.Text)
    
    # Relationships
    case = db.relationship('Case', backref='ioc_matches')
    ioc = db.relationship('IOC', backref='matches')
    reviewer = db.relationship('User', backref='reviewed_ioc_matches')
    
    def __repr__(self):
        return f'<IOCMatch IOC:{self.ioc_id} Event:{self.event_id[:8]}>'
```

---

## API Endpoints

### IOC Management

#### 1. **POST /ioc/add** - Add Single IOC
```python
@app.route('/ioc/add', methods=['POST'])
@login_required
def add_ioc():
    """Add a single IOC to active case"""
    # Form fields: ioc_type, ioc_value, description, source, severity, confidence
    # Normalize value (lowercase for comparison)
    # Check for duplicates
    # Insert into database
    # Log audit event
```

#### 2. **POST /ioc/bulk-import** - Import Multiple IOCs
```python
@app.route('/ioc/bulk-import', methods=['POST'])
@login_required
def bulk_import_iocs():
    """Import IOCs from CSV or text file"""
    # CSV format: type,value,description,source,severity,confidence
    # Text format: one IOC per line (auto-detect type)
    # Parse file
    # Validate each IOC
    # Bulk insert with duplicate checking
    # Return summary (added, duplicates, errors)
```

#### 3. **GET /ioc/list** - List Case IOCs
```python
@app.route('/ioc/list')
@login_required
def list_iocs():
    """Display all IOCs for active case"""
    # Filter by type, severity, status
    # Sort by match_count, added_at, severity
    # Paginate results
    # Show match counts and last_seen
```

#### 4. **POST /ioc/edit/<int:ioc_id>** - Edit IOC
```python
@app.route('/ioc/edit/<int:ioc_id>', methods=['POST'])
@login_required
def edit_ioc(ioc_id):
    """Update IOC details"""
    # Update description, severity, confidence, notes
    # Mark as false positive
    # Deactivate/activate
```

#### 5. **POST /ioc/delete/<int:ioc_id>** - Delete IOC
```python
@app.route('/ioc/delete/<int:ioc_id>', methods=['POST'])
@login_required
def delete_ioc(ioc_id):
    """Delete IOC and associated matches"""
    # Cascade delete matches
    # Log audit event
```

### Threat Hunting

#### 6. **POST /ioc/hunt** - Hunt for IOCs
```python
@app.route('/ioc/hunt', methods=['POST'])
@login_required
def hunt_iocs():
    """Search indexed events for all active IOCs"""
    # Background Celery task
    # Query OpenSearch for each IOC
    # Field mapping based on IOC type:
    #   - ip: Computer, SourceAddress, DestinationAddress, etc.
    #   - hash_*: Hashes.MD5, Hashes.SHA256, etc.
    #   - filename: Image, ParentImage, TargetFilename, etc.
    #   - domain: DestinationHostname, QueryName, etc.
    # Create IOCMatch records
    # Update IOC.match_count and last_seen
    # Return real-time progress
```

#### 7. **GET /ioc/matches** - View IOC Matches
```python
@app.route('/ioc/matches')
@login_required
def view_ioc_matches():
    """Display all IOC matches for case"""
    # Filter by IOC, severity, reviewed status
    # Sort by timestamp, IOC type
    # Show event details
    # Mark as reviewed
    # Add analyst notes
```

#### 8. **GET /api/ioc/hunt/progress/<task_id>** - Hunt Progress
```python
@app.route('/api/ioc/hunt/progress/<task_id>')
@login_required
def ioc_hunt_progress(task_id):
    """Get real-time progress of IOC hunting task"""
    # Return: current_ioc, total_iocs, matches_found, percent_complete
```

---

## Celery Background Task

### IOC Hunting Task

```python
@celery_app.task(bind=True, name='tasks.hunt_iocs')
def hunt_iocs(self, case_id):
    """
    Background task to hunt for all active IOCs in case events
    
    Process:
    1. Get all active IOCs for case
    2. For each IOC:
       a. Build OpenSearch query based on IOC type
       b. Search all case indices
       c. Create IOCMatch records for hits
       d. Update IOC.match_count and last_seen
       e. Update progress
    3. Return summary
    """
    
    # IOC Type to Field Mappings
    ioc_field_mapping = {
        'ip': [
            'Computer', 'SourceAddress', 'DestinationAddress', 
            'IpAddress', 'ClientIP', 'ServerIP'
        ],
        'hash_md5': [
            'Hashes.MD5', 'MD5', 'hash.md5'
        ],
        'hash_sha256': [
            'Hashes.SHA256', 'SHA256', 'hash.sha256'
        ],
        'filename': [
            'Image', 'ParentImage', 'TargetFilename', 
            'FileName', 'process_name'
        ],
        'domain': [
            'DestinationHostname', 'QueryName', 'domain'
        ],
        'process_name': [
            'Image', 'ParentImage', 'CommandLine', 'process_name'
        ]
    }
    
    # Build multi-field query for each IOC
    # Use "should" clause to match any field
    # Store matches in ioc_match table
    # Update progress via self.update_state()
```

---

## User Interface

### 1. IOC Management Page (`/ioc/list`)

**Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ IOC Management - [Case Name]                                │
├─────────────────────────────────────────────────────────────┤
│ [+ Add IOC] [📁 Bulk Import] [🔍 Hunt All] [📊 View Matches]│
├─────────────────────────────────────────────────────────────┤
│ Filters:                                                     │
│ Type: [All ▼] Severity: [All ▼] Status: [Active ▼]        │
│ Search: [____________] [🔍]                                  │
├─────────────────────────────────────────────────────────────┤
│ IOCs (45 total, 12 with matches)                           │
├────┬──────┬──────────────┬─────────┬────────┬──────────────┤
│Type│Value │Description   │Severity │Matches │Actions       │
├────┼──────┼──────────────┼─────────┼────────┼──────────────┤
│IP  │1.2.3.4│C2 Server    │Critical │⚠️ 23  │[View][Edit]  │
│Hash│abc...│Malware      │High     │🔍 15   │[View][Edit]  │
│...                                                          │
└─────────────────────────────────────────────────────────────┘
```

### 2. Add IOC Modal

**Form Fields:**
- IOC Type (dropdown): IP, Domain, Hash (MD5/SHA1/SHA256), Email, URL, Filename, Process Name, Registry Key, User Account
- IOC Value (text input with validation)
- Description (textarea)
- Source (text): e.g., "VirusTotal", "OSINT", "Internal Analysis"
- Severity (dropdown): Low, Medium, High, Critical
- Confidence (dropdown): Low, Medium, High
- Notes (textarea)

### 3. Bulk Import Page

**Features:**
- Upload CSV file
- Paste text (one IOC per line)
- Format examples shown
- Preview before import
- Validation with error reporting
- Summary of imported/skipped/errors

### 4. IOC Matches Page (`/ioc/matches`)

**Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ IOC Matches - [Case Name]                                   │
├─────────────────────────────────────────────────────────────┤
│ Filters:                                                     │
│ IOC Type: [All ▼] Severity: [All ▼] Reviewed: [All ▼]     │
├─────────────────────────────────────────────────────────────┤
│ 156 matches found                                           │
├──────────┬────────────┬──────────┬──────────┬──────────────┤
│Timestamp │IOC         │Event     │Field     │Actions       │
├──────────┼────────────┼──────────┼──────────┼──────────────┤
│2025-09-01│1.2.3.4 (IP)│EDR event │dest_ip   │[View][Mark]  │
│...                                                          │
└─────────────────────────────────────────────────────────────┘
```

### 5. Integration in Case Dashboard

Add new tile:
```
┌──────────────────────────┐
│ 🎯 IOC Threat Hunting    │
├──────────────────────────┤
│ 45 IOCs tracked          │
│ 156 matches found        │
│ 23 unreviewed            │
│                          │
│ [Manage IOCs]            │
│ [Hunt Now]               │
│ [View Matches]           │
└──────────────────────────┘
```

### 6. IOC Indicators in Search Results

Add IOC match badge to events:
```
┌─────────────────────────────────────────────┐
│ Event: 4624                                  │
│ 🎯 IOC MATCH: 1.2.3.4 (C2 Server - Critical)│
│ Timestamp: 2025-09-01 10:30:00              │
│ Computer: WORKSTATION01                      │
└─────────────────────────────────────────────┘
```

---

## Threat Hunting Workflow

### Typical Use Case:

1. **Analyst receives threat intel**: New C2 server IP identified
2. **Add IOC**: Go to IOC Management → Add IOC
   - Type: IP Address
   - Value: 192.168.1.100
   - Description: APT29 C2 Server
   - Source: CrowdStrike Intel
   - Severity: Critical
3. **Hunt**: Click "Hunt All" button
   - Background task scans all indexed events
   - Matches stored in database
   - Real-time progress shown
4. **Review Matches**: Go to IOC Matches
   - See all events containing the IOC
   - Review each match
   - Mark false positives
   - Add notes
5. **Timeline Tag**: Tag critical matches for timeline
6. **Report**: Export IOC matches for incident report

---

## OpenSearch Query Examples

### IP Address Hunt:
```json
{
  "query": {
    "bool": {
      "should": [
        {"match": {"Computer": "192.168.1.100"}},
        {"match": {"SourceAddress": "192.168.1.100"}},
        {"match": {"DestinationAddress": "192.168.1.100"}},
        {"match": {"IpAddress": "192.168.1.100"}}
      ],
      "minimum_should_match": 1
    }
  }
}
```

### File Hash Hunt (SHA256):
```json
{
  "query": {
    "bool": {
      "should": [
        {"match": {"Hashes.SHA256": "abc123..."}},
        {"match": {"SHA256": "abc123..."}},
        {"match": {"hash.sha256": "abc123..."}}
      ],
      "minimum_should_match": 1
    }
  }
}
```

### Filename Hunt:
```json
{
  "query": {
    "bool": {
      "should": [
        {"wildcard": {"Image": "*malware.exe"}},
        {"wildcard": {"ParentImage": "*malware.exe"}},
        {"wildcard": {"TargetFilename": "*malware.exe"}},
        {"wildcard": {"process_name": "*malware.exe"}}
      ],
      "minimum_should_match": 1
    }
  }
}
```

---

## Migration Script

### `migrate_ioc_management.py`

```python
#!/usr/bin/env python3
"""
Database migration to add IOC management tables
Run this after updating to version 7.14.0
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, db, IOC, IOCMatch

def migrate():
    """Add ioc and ioc_match tables to database"""
    with app.app_context():
        try:
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            
            tables_to_create = []
            if 'ioc' not in inspector.get_table_names():
                tables_to_create.append('ioc')
            if 'ioc_match' not in inspector.get_table_names():
                tables_to_create.append('ioc_match')
            
            if not tables_to_create:
                print("[Migration] ✓ IOC tables already exist")
                return True
            
            print(f"[Migration] Creating tables: {', '.join(tables_to_create)}")
            db.create_all()
            print("[Migration] ✓ IOC tables created successfully")
            
            # Add audit log
            from datetime import datetime
            from main import AuditLog
            migration_log = AuditLog(
                user_id=None,
                username='system',
                action='database_migration',
                category='admin',
                details='Created IOC management tables (ioc, ioc_match) - version 7.14.0',
                ip_address='127.0.0.1',
                timestamp=datetime.utcnow(),
                success=True
            )
            db.session.add(migration_log)
            db.session.commit()
            print("[Migration] ✓ Added migration audit log entry")
            
            return True
            
        except Exception as e:
            print(f"[Migration] ✗ Error: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == '__main__':
    print("="*80)
    print("caseScope v7.14.0 Database Migration")
    print("Adding IOC management tables for threat hunting")
    print("="*80)
    
    success = migrate()
    
    if success:
        print("\n[Migration] ✓ Migration completed successfully")
        print("[Migration] IOC management is now active")
        sys.exit(0)
    else:
        print("\n[Migration] ✗ Migration failed")
        sys.exit(1)
```

---

## Benefits

1. **Centralized IOC Management**: All indicators in one place per case
2. **Automated Threat Hunting**: Scan all events for IOCs with one click
3. **Context Preservation**: Track where IOCs came from and why they matter
4. **Match Tracking**: See exactly which events contain each IOC
5. **False Positive Handling**: Mark and exclude FPs from analysis
6. **Collaborative**: Multiple analysts can add and review IOC matches
7. **Integration**: Works with existing timeline tagging and SIGMA violations
8. **Audit Trail**: All IOC operations logged
9. **Scalable**: Efficient OpenSearch queries for large datasets
10. **Flexible**: Support for multiple IOC types and sources

---

## Future Enhancements (v7.15+)

1. **STIX/TAXII Integration**: Import IOCs from threat intel feeds
2. **IOC Expiration**: Auto-deactivate IOCs after X days
3. **Watchlist Alerts**: Real-time notifications for new IOC matches
4. **IOC Correlation**: Find relationships between different IOCs
5. **External Enrichment**: Query VirusTotal, AbuseIPDB, etc.
6. **IOC Collections**: Group related IOCs (e.g., APT29 campaign)
7. **Regex IOCs**: Support pattern-based indicators
8. **Cross-Case Hunting**: Search for IOCs across all cases
9. **IOC Scoring**: Risk scores based on matches and context
10. **Export Formats**: STIX, OpenIOC, CSV

---

## Implementation Priority

### Phase 1 (v7.14.0):
- Database models (IOC, IOCMatch)
- Migration script
- Basic CRUD operations (add, edit, delete)
- IOC list page
- Manual hunt button

### Phase 2 (v7.14.1):
- Automated threat hunting (Celery task)
- Progress tracking
- Match review interface
- Bulk import (CSV/text)

### Phase 3 (v7.14.2):
- Integration with search results (IOC badges)
- Case dashboard tile
- Advanced filtering and sorting
- Export functionality

---

## Estimated Development Time

- **Database & Models**: 2 hours
- **API Endpoints**: 4 hours
- **UI Pages**: 6 hours
- **Celery Hunting Task**: 4 hours
- **Testing**: 3 hours
- **Documentation**: 1 hour

**Total**: ~20 hours for complete implementation

---

## Questions for User

1. **IOC Types Priority**: Which IOC types are most important for your use cases?
   - IP addresses
   - File hashes
   - Domains
   - Filenames
   - Others?

2. **Import Formats**: What format do you typically receive threat intel in?
   - CSV
   - Plain text lists
   - STIX/TAXII
   - JSON
   - Other?

3. **Automation**: Should IOC hunting run automatically after adding IOCs, or manual trigger only?

4. **Alerting**: Do you need real-time alerts when new events match existing IOCs?

5. **Integration**: Any external threat intel platforms you want to integrate with?

---

**Ready to implement?** Let me know which phase to start with!

