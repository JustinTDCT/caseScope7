#!/usr/bin/env python3
"""
Enable Windows threat-hunting SIGMA rules
Looks for rules with 'windows' in category and threat-hunting indicators
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from main import app, db, SigmaRule
import json

print("="*80)
print("ENABLING WINDOWS THREAT HUNTING RULES")
print("="*80)
print()

with app.app_context():
    all_rules = SigmaRule.query.all()
    
    print(f"Scanning {len(all_rules)} rules...")
    print()
    
    # Find Windows threat-hunting rules
    windows_threat_rules = []
    
    for rule in all_rules:
        # Check category for Windows
        category_lower = (rule.category or '').lower()
        is_windows = 'windows' in category_lower
        
        # Check for threat hunting indicators in tags, title, description
        tags_str = rule.tags or '[]'
        try:
            tags_list = json.loads(tags_str)
            tags_lower = ' '.join([str(t).lower() for t in tags_list])
        except:
            tags_lower = tags_str.lower()
        
        title_lower = (rule.title or '').lower()
        desc_lower = (rule.description or '').lower()
        
        is_threat_hunting = any(indicator in (tags_lower + ' ' + title_lower + ' ' + desc_lower) for indicator in [
            'threat', 'hunting', 'anomaly', 'suspicious', 'detection'
        ])
        
        # Also check YAML content for path indicators
        yaml_has_threat_hunting = False
        if rule.rule_yaml:
            yaml_has_threat_hunting = 'threat-hunting' in rule.rule_yaml.lower() or 'threat_hunting' in rule.rule_yaml.lower()
        
        if is_windows and (is_threat_hunting or yaml_has_threat_hunting):
            windows_threat_rules.append(rule)
    
    print(f"Found {len(windows_threat_rules)} Windows threat-hunting rules")
    print()
    
    if windows_threat_rules:
        enabled_count = 0
        already_enabled = 0
        
        for rule in windows_threat_rules:
            if not rule.is_enabled:
                rule.is_enabled = True
                enabled_count += 1
                print(f"✓ Enabled: {rule.title} [Level: {rule.level}]")
            else:
                already_enabled += 1
        
        db.session.commit()
        
        print()
        print("="*80)
        print(f"SUMMARY:")
        print(f"  Newly enabled: {enabled_count}")
        print(f"  Already enabled: {already_enabled}")
        print(f"  Total Windows threat-hunting rules: {len(windows_threat_rules)}")
        print()
        
        # Show total enabled rules
        total_enabled = SigmaRule.query.filter_by(is_enabled=True).count()
        print(f"  Total enabled rules in database: {total_enabled}")
        print("="*80)
    else:
        print("No Windows threat-hunting rules found!")
        print()
        print(f"Total rules in database: {len(all_rules)}")
        print()
        print("Checking categories:")
        categories = {}
        for rule in all_rules:
            cat = rule.category or 'unknown'
            categories[cat] = categories.get(cat, 0) + 1
        
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {cat}: {count}")
