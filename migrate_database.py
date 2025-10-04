#!/usr/bin/env python3
"""
caseScope 7.x Unified Database Migration Script
Runs all necessary database schema migrations in correct order
"""

import sys
import os
import sqlite3
from datetime import datetime

# ANSI color codes for output
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'  # No Color

def log(message):
    """Print timestamped log message"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{GREEN}[{timestamp}]{NC} {message}")

def log_error(message):
    """Print timestamped error message"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{RED}[{timestamp}] ERROR:{NC} {message}", file=sys.stderr)

def log_warning(message):
    """Print timestamped warning message"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{YELLOW}[{timestamp}] WARNING:{NC} {message}")

def check_column_exists(cursor, table, column):
    """Check if a column exists in a table"""
    cursor.execute(f"PRAGMA table_info({table})")
    columns = [row[1] for row in cursor.fetchall()]
    return column in columns

def check_table_exists(cursor, table):
    """Check if a table exists"""
    cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
    return cursor.fetchone() is not None

def migrate_audit_log(conn):
    """Add audit logging table and fields"""
    log("→ Checking audit_log migrations...")
    cursor = conn.cursor()
    
    if not check_table_exists(cursor, 'audit_log'):
        log("  Creating audit_log table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username VARCHAR(100),
                action VARCHAR(200) NOT NULL,
                category VARCHAR(50) NOT NULL,
                details TEXT,
                ip_address VARCHAR(45),
                success BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES user(id)
            )
        ''')
        conn.commit()
        log(f"  {GREEN}✓{NC} audit_log table created")
    else:
        log(f"  {GREEN}✓{NC} audit_log table already exists")

def migrate_search_enhancements(conn):
    """Add search history and saved searches"""
    log("→ Checking search enhancement migrations...")
    cursor = conn.cursor()
    
    # SearchHistory table
    if not check_table_exists(cursor, 'search_history'):
        log("  Creating search_history table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS search_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                query_string TEXT NOT NULL,
                result_count INTEGER,
                filters TEXT,
                executed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES "case"(id),
                FOREIGN KEY (user_id) REFERENCES user(id)
            )
        ''')
        conn.commit()
        log(f"  {GREEN}✓{NC} search_history table created")
    else:
        log(f"  {GREEN}✓{NC} search_history table already exists")
    
    # SavedSearch table
    if not check_table_exists(cursor, 'saved_search'):
        log("  Creating saved_search table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS saved_search (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                name VARCHAR(200) NOT NULL,
                query_string TEXT NOT NULL,
                filters TEXT,
                description TEXT,
                is_shared BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                use_count INTEGER DEFAULT 0,
                FOREIGN KEY (case_id) REFERENCES "case"(id),
                FOREIGN KEY (user_id) REFERENCES user(id)
            )
        ''')
        conn.commit()
        log(f"  {GREEN}✓{NC} saved_search table created")
    else:
        log(f"  {GREEN}✓{NC} saved_search table already exists")

def migrate_case_management(conn):
    """Add case management fields"""
    log("→ Checking case management migrations...")
    cursor = conn.cursor()
    
    # CaseTemplate table
    if not check_table_exists(cursor, 'case_template'):
        log("  Creating case_template table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS case_template (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(200) NOT NULL,
                description TEXT,
                default_priority VARCHAR(20),
                default_tags TEXT,
                checklist TEXT,
                is_default BOOLEAN DEFAULT 0,
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES user(id)
            )
        ''')
        conn.commit()
        log(f"  {GREEN}✓{NC} case_template table created")
    else:
        log(f"  {GREEN}✓{NC} case_template table already exists")
    
    # Add fields to case table
    case_fields = [
        ('assignee_id', 'INTEGER', 'ALTER TABLE "case" ADD COLUMN assignee_id INTEGER'),
        ('closed_at', 'DATETIME', 'ALTER TABLE "case" ADD COLUMN closed_at DATETIME'),
        ('closed_by', 'INTEGER', 'ALTER TABLE "case" ADD COLUMN closed_by INTEGER'),
        ('template_id', 'INTEGER', 'ALTER TABLE "case" ADD COLUMN template_id INTEGER'),
        ('tags', 'TEXT', 'ALTER TABLE "case" ADD COLUMN tags TEXT')
    ]
    
    for field_name, field_type, alter_sql in case_fields:
        if not check_column_exists(cursor, 'case', field_name):
            log(f"  Adding {field_name} to case table...")
            cursor.execute(alter_sql)
            conn.commit()
            log(f"  {GREEN}✓{NC} {field_name} added")
        else:
            log(f"  {GREEN}✓{NC} {field_name} already exists")

def migrate_timeline_tags(conn):
    """Add timeline event tagging"""
    log("→ Checking timeline tag migrations...")
    cursor = conn.cursor()
    
    if not check_table_exists(cursor, 'event_tag'):
        log("  Creating event_tag table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS event_tag (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                event_id VARCHAR(100) NOT NULL,
                index_name VARCHAR(200) NOT NULL,
                event_timestamp DATETIME,
                tag_type VARCHAR(50) NOT NULL,
                color VARCHAR(20),
                notes TEXT,
                tagged_by INTEGER NOT NULL,
                tagged_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES "case"(id),
                FOREIGN KEY (tagged_by) REFERENCES user(id)
            )
        ''')
        conn.commit()
        log(f"  {GREEN}✓{NC} event_tag table created")
    else:
        log(f"  {GREEN}✓{NC} event_tag table already exists")

def migrate_ioc_management(conn):
    """Add IOC management tables"""
    log("→ Checking IOC management migrations...")
    cursor = conn.cursor()
    
    # IOC table
    if not check_table_exists(cursor, 'ioc'):
        log("  Creating ioc table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                ioc_type VARCHAR(50) NOT NULL,
                ioc_value TEXT NOT NULL,
                description TEXT,
                severity VARCHAR(20) DEFAULT 'medium',
                is_active BOOLEAN DEFAULT 1,
                hunt_type VARCHAR(20) DEFAULT 'both',
                added_by INTEGER NOT NULL,
                added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_hunted DATETIME,
                match_count INTEGER DEFAULT 0,
                FOREIGN KEY (case_id) REFERENCES "case"(id),
                FOREIGN KEY (added_by) REFERENCES user(id)
            )
        ''')
        conn.commit()
        log(f"  {GREEN}✓{NC} ioc table created")
    else:
        log(f"  {GREEN}✓{NC} ioc table already exists")

def migrate_ioc_matches(conn):
    """Add IOC matches tracking"""
    log("→ Checking IOC matches migrations...")
    cursor = conn.cursor()
    
    if not check_table_exists(cursor, 'ioc_match'):
        log("  Creating ioc_match table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_match (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_id INTEGER NOT NULL,
                case_id INTEGER NOT NULL,
                file_id INTEGER NOT NULL,
                event_id VARCHAR(100) NOT NULL,
                index_name VARCHAR(200) NOT NULL,
                matched_field VARCHAR(200),
                matched_value TEXT,
                event_timestamp DATETIME,
                source_filename VARCHAR(500),
                detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ioc_id) REFERENCES ioc(id),
                FOREIGN KEY (case_id) REFERENCES "case"(id),
                FOREIGN KEY (file_id) REFERENCES case_file(id)
            )
        ''')
        conn.commit()
        log(f"  {GREEN}✓{NC} ioc_match table created")
    else:
        log(f"  {GREEN}✓{NC} ioc_match table already exists")

def migrate_system_settings(conn):
    """Add system settings table"""
    log("→ Checking system settings migrations...")
    cursor = conn.cursor()
    
    if not check_table_exists(cursor, 'system_settings'):
        log("  Creating system_settings table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key VARCHAR(100) UNIQUE NOT NULL,
                setting_value TEXT,
                setting_type VARCHAR(20) DEFAULT 'string',
                description TEXT,
                is_encrypted BOOLEAN DEFAULT 0,
                updated_by INTEGER,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (updated_by) REFERENCES user(id)
            )
        ''')
        conn.commit()
        log(f"  {GREEN}✓{NC} system_settings table created")
    else:
        log(f"  {GREEN}✓{NC} system_settings table already exists")

def migrate_case_company(conn):
    """Add company field to cases for DFIR-IRIS integration"""
    log("→ Checking case company migrations...")
    cursor = conn.cursor()
    
    # Add company fields to case table
    company_fields = [
        ('company', 'VARCHAR(200)', 'ALTER TABLE "case" ADD COLUMN company VARCHAR(200)'),
        ('iris_company_id', 'INTEGER', 'ALTER TABLE "case" ADD COLUMN iris_company_id INTEGER'),
        ('iris_case_id', 'INTEGER', 'ALTER TABLE "case" ADD COLUMN iris_case_id INTEGER'),
        ('iris_synced_at', 'DATETIME', 'ALTER TABLE "case" ADD COLUMN iris_synced_at DATETIME')
    ]
    
    for field_name, field_type, alter_sql in company_fields:
        if not check_column_exists(cursor, 'case', field_name):
            log(f"  Adding {field_name} to case table...")
            cursor.execute(alter_sql)
            conn.commit()
            log(f"  {GREEN}✓{NC} {field_name} added")
        else:
            log(f"  {GREEN}✓{NC} {field_name} already exists")

def main():
    """Run all database migrations"""
    db_path = '/opt/casescope/data/casescope.db'
    
    log(f"{BLUE}═══════════════════════════════════════════════════════════════{NC}")
    log(f"{BLUE}           caseScope Database Migration Tool                   {NC}")
    log(f"{BLUE}═══════════════════════════════════════════════════════════════{NC}")
    log("")
    
    # Check database exists
    if not os.path.exists(db_path):
        log_error(f"Database not found at {db_path}")
        log_error("Run installation first to create database")
        return 1
    
    log(f"Database: {db_path}")
    log("")
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        log(f"{GREEN}✓{NC} Connected to database")
        log("")
        
        # Run migrations in order
        migrate_audit_log(conn)
        migrate_search_enhancements(conn)
        migrate_case_management(conn)
        migrate_timeline_tags(conn)
        migrate_ioc_management(conn)
        migrate_ioc_matches(conn)
        migrate_system_settings(conn)
        migrate_case_company(conn)
        
        conn.close()
        log("")
        log(f"{GREEN}═══════════════════════════════════════════════════════════════{NC}")
        log(f"{GREEN}           All migrations completed successfully!              {NC}")
        log(f"{GREEN}═══════════════════════════════════════════════════════════════{NC}")
        return 0
        
    except sqlite3.Error as e:
        log_error(f"Database error: {e}")
        log_error("Migration failed!")
        return 1
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())

