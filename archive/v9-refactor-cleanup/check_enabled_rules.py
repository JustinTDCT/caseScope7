#!/usr/bin/env python3
"""
Check how many SIGMA rules are currently enabled
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from main import app, db, SigmaRule

print("="*80)
print("SIGMA RULES STATUS")
print("="*80)
print()

with app.app_context():
    total = SigmaRule.query.count()
    enabled = SigmaRule.query.filter_by(is_enabled=True).count()
    disabled = SigmaRule.query.filter_by(is_enabled=False).count()
    
    print(f"Total rules: {total}")
    print(f"Enabled: {enabled}")
    print(f"Disabled: {disabled}")
    print()
    
    if enabled > 0:
        print(f"Sample of enabled rules:")
        for rule in SigmaRule.query.filter_by(is_enabled=True).limit(20).all():
            print(f"  ✓ {rule.title} ({rule.level})")
        print()
    
    # Check for rules with specific tags
    print("Checking for rules with 'attack.' tags (MITRE ATT&CK)...")
    attack_rules = []
    for rule in SigmaRule.query.limit(100).all():
        if 'attack.' in (rule.tags or '').lower():
            attack_rules.append(rule)
    
    if attack_rules:
        print(f"Found {len(attack_rules)} rules with MITRE ATT&CK tags in first 100 rules")
        print("Sample:")
        for rule in attack_rules[:5]:
            print(f"  - {rule.title}")
            print(f"    Tags: {rule.tags[:100]}...")
    
    print()
    print("="*80)
