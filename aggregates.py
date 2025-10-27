#!/usr/bin/env python3
"""
caseScope v9.4.0 - Case Aggregation Helper
Copyright (c) 2025 Justin Dube <casescope@thedubes.net>

Helper functions for updating Case-level aggregate statistics from CaseFile data.
This replaces expensive OpenSearch queries with fast DB operations.
"""

from models import db, Case, CaseFile, EventTag
from sqlalchemy import func
import logging

logger = logging.getLogger(__name__)


def update_case_aggregates(case_id):
    """
    Recalculate and update Case-level aggregate statistics from CaseFile rows.
    
    This function:
    1. Queries all non-deleted files in the case
    2. Calculates SUM/COUNT aggregates
    3. Updates the Case record
    
    Called after:
    - File indexing completes
    - SIGMA processing completes
    - IOC hunting completes
    - File deletion
    - File re-indexing
    
    Args:
        case_id (int): The case ID to update
    
    Returns:
        dict: Updated statistics
    """
    try:
        # Query aggregates from CaseFile table
        aggregates = db.session.query(
            func.count(CaseFile.id).label('total_files'),
            func.coalesce(func.sum(CaseFile.event_count), 0).label('total_events'),
            func.coalesce(func.sum(CaseFile.ioc_event_count), 0).label('total_events_with_iocs'),
            func.coalesce(func.sum(CaseFile.sigma_event_count), 0).label('total_events_with_sigma')
        ).filter(
            CaseFile.case_id == case_id,
            CaseFile.is_deleted == False,
            CaseFile.is_hidden == False  # Only count visible files
        ).first()
        
        # Get the case - use db.session.get() instead of Case.query.get()
        case = db.session.get(Case, case_id)
        if not case:
            logger.error(f"Case {case_id} not found for aggregate update")
            return None
        
        # Update case statistics using setattr (safer than direct assignment)
        setattr(case, 'total_files', aggregates.total_files or 0)
        setattr(case, 'total_events', int(aggregates.total_events or 0))
        setattr(case, 'total_events_with_iocs', int(aggregates.total_events_with_iocs or 0))
        setattr(case, 'total_events_with_sigma', int(aggregates.total_events_with_sigma or 0))
        
        db.session.commit()
        
        stats = {
            'total_files': case.total_files,
            'total_events': case.total_events,
            'total_events_with_iocs': case.total_events_with_iocs,
            'total_events_with_sigma': case.total_events_with_sigma
        }
        
        logger.info(f"Updated Case {case_id} aggregates: {stats}")
        return stats
        
    except Exception as e:
        logger.error(f"Failed to update Case {case_id} aggregates: {e}")
        db.session.rollback()
        return None


def update_file_tagged_status(file_id):
    """
    Update the is_tagged flag for a file based on EventTag records.
    
    Args:
        file_id (int): The file ID to check
    
    Returns:
        bool: Whether the file has tags
    """
    try:
        case_file = CaseFile.query.get(file_id)
        if not case_file:
            logger.error(f"File {file_id} not found for tagged status update")
            return False
        
        # Check if file has any tagged events
        # EventTags store the opensearch_key in index_name field
        has_tags = db.session.query(EventTag).filter(
            EventTag.case_id == case_file.case_id,
            EventTag.index_name == case_file.opensearch_key
        ).count() > 0
        
        case_file.is_tagged = has_tags
        db.session.commit()
        
        logger.debug(f"Updated File {file_id} tagged status: {has_tags}")
        return has_tags
        
    except Exception as e:
        logger.error(f"Failed to update File {file_id} tagged status: {e}")
        db.session.rollback()
        return False


def recalculate_all_case_aggregates():
    """
    Recalculate aggregates for ALL cases in the database.
    Useful for initial migration or after bulk operations.
    
    Returns:
        dict: Summary of updates
    """
    try:
        cases = Case.query.filter_by(is_active=True).all()
        total = len(cases)
        updated = 0
        failed = 0
        
        logger.info(f"Recalculating aggregates for {total} cases...")
        
        for case in cases:
            result = update_case_aggregates(case.id)
            if result:
                updated += 1
            else:
                failed += 1
        
        summary = {
            'total_cases': total,
            'updated': updated,
            'failed': failed
        }
        
        logger.info(f"Recalculation complete: {summary}")
        return summary
        
    except Exception as e:
        logger.error(f"Failed to recalculate all case aggregates: {e}")
        return None

