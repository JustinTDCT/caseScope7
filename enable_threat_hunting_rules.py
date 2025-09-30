#!/usr/bin/env python3
"""
Enable all SIGMA rules from the threat-hunting/windows directory
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from main import app, db, SigmaRule

print("="*80)
print("ENABLING THREAT HUNTING WINDOWS RULES")
print("="*80)
print()

with app.app_context():
    # Find all rules from threat-hunting/windows directory
    # Check the rule_yaml content since that's where the file path is stored
    all_rules = SigmaRule.query.all()
    threat_hunting_rules = [
        rule for rule in all_rules 
        if 'threat-hunting/windows' in (rule.rule_yaml or '').lower()
        or 'threat_hunting/windows' in (rule.category or '').lower()
    ]
    
    if not threat_hunting_rules:
        print("No threat-hunting rules found!")
        print()
        print("Checking what rules exist...")
        all_rules = SigmaRule.query.all()
        print(f"Total rules in database: {len(all_rules)}")
        
        if all_rules:
            print("\nSample rules:")
            for rule in all_rules[:10]:
                print(f"  - {rule.title}")
                print(f"    Category: {rule.category}")
                print(f"    File path: {rule.file_path}")
                print()
    else:
        print(f"Found {len(threat_hunting_rules)} threat-hunting rules")
        print()
        
        enabled_count = 0
        for rule in threat_hunting_rules:
            if not rule.is_enabled:
                rule.is_enabled = True
                enabled_count += 1
                print(f"✓ Enabled: {rule.title}")
            else:
                print(f"  Already enabled: {rule.title}")
        
        db.session.commit()
        
        print()
        print("="*80)
        print(f"SUMMARY: Enabled {enabled_count} new rules")
        print(f"Total threat-hunting rules now enabled: {len(threat_hunting_rules)}")
        print("="*80)
