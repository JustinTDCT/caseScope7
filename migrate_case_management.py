#!/usr/bin/env python3
"""
Migration script for Case Management features
Adds: assignee_id, closed_at, closed_by, template_id, tags to Case model
Creates: CaseTemplate table
"""

import sys
import os
from sqlalchemy import create_engine, text, inspect
from datetime import datetime

def migrate_case_management():
    """Add Case Management fields to Case table and create CaseTemplate table"""
    
    db_path = '/opt/casescope/data/casescope.db'
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found at {db_path}")
        return False
    
    try:
        engine = create_engine(f'sqlite:///{db_path}')
        inspector = inspect(engine)
        
        with engine.connect() as conn:
            print("🔍 Checking Case table structure...")
            
            # Check if Case table exists
            if 'case' not in inspector.get_table_names():
                print("❌ Case table does not exist")
                return False
            
            # Get current columns
            existing_columns = [col['name'] for col in inspector.get_columns('case')]
            print(f"   Current columns: {', '.join(existing_columns)}")
            
            # Add new columns to Case table if they don't exist
            new_columns = {
                'assignee_id': 'ALTER TABLE "case" ADD COLUMN assignee_id INTEGER REFERENCES user(id)',
                'closed_at': 'ALTER TABLE "case" ADD COLUMN closed_at DATETIME',
                'closed_by': 'ALTER TABLE "case" ADD COLUMN closed_by INTEGER REFERENCES user(id)',
                'template_id': 'ALTER TABLE "case" ADD COLUMN template_id INTEGER REFERENCES case_template(id)',
                'tags': 'ALTER TABLE "case" ADD COLUMN tags VARCHAR(500)'
            }
            
            for col_name, alter_sql in new_columns.items():
                if col_name not in existing_columns:
                    print(f"   Adding column: {col_name}")
                    conn.execute(text(alter_sql))
                    conn.commit()
                else:
                    print(f"   ✓ Column {col_name} already exists")
            
            # Create CaseTemplate table if it doesn't exist
            if 'case_template' not in inspector.get_table_names():
                print("\n📝 Creating case_template table...")
                create_table_sql = """
                CREATE TABLE case_template (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(200) NOT NULL UNIQUE,
                    description TEXT,
                    default_priority VARCHAR(20) DEFAULT 'Medium',
                    default_tags VARCHAR(500),
                    checklist TEXT,
                    created_by INTEGER NOT NULL REFERENCES user(id),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
                """
                conn.execute(text(create_table_sql))
                conn.commit()
                print("   ✓ case_template table created")
                
                # Insert default templates
                print("\n📋 Creating default case templates...")
                default_templates = [
                    {
                        'name': 'Incident Response',
                        'description': 'Standard incident response investigation',
                        'priority': 'High',
                        'tags': 'incident,security,investigation',
                        'checklist': '["Identify scope", "Preserve evidence", "Contain threat", "Eradicate malware", "Recover systems", "Post-incident review"]'
                    },
                    {
                        'name': 'Forensic Analysis',
                        'description': 'Digital forensic examination',
                        'priority': 'Medium',
                        'tags': 'forensics,analysis,evidence',
                        'checklist': '["Acquire evidence", "Validate integrity", "Analyze artifacts", "Document findings", "Generate report"]'
                    },
                    {
                        'name': 'Threat Hunt',
                        'description': 'Proactive threat hunting operation',
                        'priority': 'Medium',
                        'tags': 'threat-hunt,proactive,detection',
                        'checklist': '["Define hypothesis", "Gather data", "Analyze events", "Identify IOCs", "Document findings", "Update detections"]'
                    }
                ]
                
                # Get first admin user as creator
                result = conn.execute(text("SELECT id FROM user WHERE role = 'administrator' LIMIT 1"))
                admin_user = result.fetchone()
                
                if admin_user:
                    admin_id = admin_user[0]
                    for template in default_templates:
                        insert_sql = """
                        INSERT INTO case_template (name, description, default_priority, default_tags, checklist, created_by, is_active)
                        VALUES (:name, :description, :priority, :tags, :checklist, :creator, 1)
                        """
                        conn.execute(text(insert_sql), {
                            'name': template['name'],
                            'description': template['description'],
                            'priority': template['priority'],
                            'tags': template['tags'],
                            'checklist': template['checklist'],
                            'creator': admin_id
                        })
                        print(f"   ✓ Created template: {template['name']}")
                    conn.commit()
                else:
                    print("   ⚠️  No admin user found, skipping default templates")
            else:
                print("\n✓ case_template table already exists")
            
            print("\n✅ Case Management migration completed successfully!")
            return True
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = migrate_case_management()
    sys.exit(0 if success else 1)

