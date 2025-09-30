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
    # The file path was checked during import but not stored in the DB
    # However, threat-hunting rules often have specific tags or references
    # Let's check all rules and look for threat-hunting indicators
    all_rules = SigmaRule.query.all()
    
    print(f"Scanning {len(all_rules)} rules for threat-hunting indicators...")
    print()
    
    # Check for rules with threat_hunting in tags or title
    threat_hunting_rules = []
    for rule in all_rules:
        # Check tags (stored as JSON)
        tags_lower = (rule.tags or '').lower()
        title_lower = (rule.title or '').lower()
        
        # Look for threat hunting indicators
        if any(indicator in tags_lower or indicator in title_lower for indicator in [
            'threat_hunting', 'threat-hunting', 'hunting', 'anomaly'
        ]):
            threat_hunting_rules.append(rule)
    
    if not threat_hunting_rules:
        print("No threat-hunting rules found!")
        print()
        print("Checking what rules exist...")
        print(f"Total rules in database: {len(all_rules)}")
        
        if all_rules:
            print("\nSample rules (checking for threat-hunting path in YAML):")
            for rule in all_rules[:10]:
                print(f"  - {rule.title}")
                print(f"    Category: {rule.category}")
                # Check if rule_yaml contains path info
                if rule.rule_yaml and 'rules-threat-hunting' in rule.rule_yaml:
                    print(f"    ⭐ THREAT HUNTING RULE FOUND!")
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
