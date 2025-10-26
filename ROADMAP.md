# caseScope Feature Roadmap

**Last Updated:** 2025-10-26  
**Current Version:** v9.0.0

This document tracks planned features and enhancements for caseScope.

---

## Priority 1: Search & Navigation Enhancements

### 1. Local Upload Folder Processing (✅ COMPLETED - v9.1.0)
**Status:** Completed  
**Priority:** High  
**Estimated Effort:** 2-3 hours  

**Description:**  
Allow users to drop files into a local folder on the server and process them with a single button click instead of uploading via web interface. Perfect for bulk processing and automation.

**Features:**
- System setting for local upload folder path (default: `/opt/casescope/local_uploads/`)
- "Process Local Uploads" button on upload page
- Background task scans folder for ZIP/EVTX/JSON files
- ZIP files automatically decompressed
- EVTX and JSON files processed normally
- Original files cleaned up after successful processing
- Audit log of processed files

**Use Cases:**
- Drop 100 ZIP files in folder, click button, walk away
- Integration with external scripts
- Faster than web upload for local processing
- Matches user's bash workflow

---

### 2. Pagination on Files List
**Status:** Planned  
**Priority:** High  
**Estimated Effort:** 2-3 hours  

**Description:**  
Add pagination to the files list page to improve performance and usability when cases have hundreds or thousands of files.

**Requirements:**
- Display 50-100 files per page (configurable)
- Show page numbers with next/previous buttons
- Display total file count and current page range
- Maintain sort order across pages
- Preserve filters when navigating pages

**Implementation Notes:**
- Use SQLAlchemy `.limit()` and `.offset()` for database queries
- Add pagination controls to files list UI
- Store pagination state in session or URL parameters

**Files to Modify:**
- `main.py` - `/files` and `/file-management` routes
- Frontend JavaScript for pagination controls

---

### 2. File Filtering During Event Search
**Status:** Planned  
**Priority:** High  
**Estimated Effort:** 4-5 hours  

**Description:**  
Add ability to include/exclude specific files when searching events. Default would be "include all, exclude none" with ability to select multiple files for inclusion/exclusion.

**Requirements:**
- **UI Component:** Multi-select dropdown for file inclusion/exclusion
- **Default Behavior:** Include all files, exclude none
- **Include Mode:** Search only selected files
- **Exclude Mode:** Search all files except selected ones
- **Combined Mode:** Support both include and exclude lists
- **Persistence:** Remember file filter selections during session
- **Visual Feedback:** Show which files are included/excluded in search results

**Implementation Notes:**
- Add file filter UI to search pages (simple, advanced, emergency)
- Modify OpenSearch queries to add `index` filter based on selected files
- Use `make_index_name()` from `utils.py` to construct index names
- Store filter state in session or as query parameters
- Show file filter summary in search results header

**OpenSearch Query Example:**
```python
# If specific files selected for inclusion:
indices = [make_index_name(case_id, filename) for filename in included_files]

# If files excluded:
all_indices = [make_index_name(case_id, f.original_filename) for f in case_files]
indices = [idx for idx in all_indices if idx not in excluded_indices]

# Search specific indices:
es.search(index=indices, body=query)
```

**Files to Modify:**
- `main.py` - `/search`, `/search/simple`, `/search/emergency` routes
- Add file filter UI component to search forms
- Modify OpenSearch query building functions

---

### 3. Event Hide/Unhide Feature
**Status:** Planned  
**Priority:** Medium  
**Estimated Effort:** 5-6 hours  

**Description:**  
Add ability to hide events from search results (similar to tagging feature). Hidden events can be reviewed via a "Show Hidden Events" checkbox.

**Requirements:**
- **Hide Action:** Mark individual events as hidden
- **Bulk Hide:** Hide multiple events at once
- **Default Behavior:** Hidden events are not shown in search results
- **Show Hidden Checkbox:** Toggle to display hidden events
- **Hidden Event Indicator:** Visual indicator when viewing hidden events
- **Unhide Action:** Restore hidden events to normal view
- **Audit Trail:** Log hide/unhide actions
- **Hidden Events Page:** Dedicated page to review all hidden events

**Database Schema:**
Add new model or extend `EventTag`:
```python
class HiddenEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    event_id = db.Column(db.String(100), nullable=False)  # OpenSearch document ID
    index_name = db.Column(db.String(200), nullable=False)
    reason = db.Column(db.Text)  # Why event was hidden
    hidden_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hidden_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    case = db.relationship('Case', backref='hidden_events')
    user = db.relationship('User', backref='hidden_events')
```

**Implementation Notes:**
- Add `HiddenEvent` model to `models.py`
- Create database migration for new table
- Add "Hide" button to event display (similar to tag button)
- Modify search queries to exclude hidden events by default
- Add "Show Hidden Events" checkbox to search UI
- Add visual indicator (grayed out, eye-slash icon) for hidden events
- Create `/hidden-events` page to review and manage hidden events
- Log hide/unhide actions to audit trail

**UI Components:**
- Hide button on individual events
- Bulk hide checkbox for multi-select
- "Show Hidden Events" toggle in search filters
- Hidden events management page
- Visual indicator for hidden events (when shown)

**Files to Modify:**
- `models.py` - Add `HiddenEvent` model
- `main.py` - Add hide/unhide routes and modify search queries
- Create database migration script
- Update search result rendering to handle hidden events

---

## Future Enhancements

### 4. Advanced Search Filters
- Field-specific searches (e.g., only search in CommandLine field)
- Saved filter presets
- Search result export (CSV, JSON)

### 5. Timeline Visualization
- Interactive timeline graph of tagged events
- Zoom and pan controls
- Event clustering for high-density periods

### 6. Collaboration Features
- Case sharing between analysts
- Comment threads on events
- Assignment and workflow tracking

### 7. Reporting
- PDF report generation
- Executive summary templates
- Automated report scheduling

---

## Implementation Priority

**Sprint 1 (Immediate):**
1. Fix critical bugs (see BUGS.md)
2. Pagination on files list
3. File filtering during search

**Sprint 2 (Next):**
1. Event hide/unhide feature
2. Search UI improvements
3. Performance optimizations

**Sprint 3 (Future):**
1. Advanced search filters
2. Timeline visualization
3. Reporting features

---

## Notes

- All features should maintain backward compatibility
- Database migrations required for new models
- Comprehensive testing before deployment
- Update version.json changelog for each feature
- Update user documentation

---

**Maintained By:** Development Team  
**Review Frequency:** Weekly during active development

