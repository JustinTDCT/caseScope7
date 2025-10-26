#!/usr/bin/env python3
"""
Show which SIGMA rules are actually enabled and what logsources they target
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from main import app, db, SigmaRule
import yaml
from collections import Counter

with app.app_context():
    enabled_rules = SigmaRule.query.filter_by(is_enabled=True).all()
    
    print(f"Total enabled rules: {len(enabled_rules)}")
    print("="*80)
    
    # Parse logsources
    logsources = []
    windows_rules = []
    linux_rules = []
    macos_rules = []
    
    for rule in enabled_rules:
        try:
            rule_dict = yaml.safe_load(rule.rule_yaml)
            logsource = rule_dict.get('logsource', {})
            product = logsource.get('product', 'unknown')
            service = logsource.get('service', 'none')
            category = logsource.get('category', 'none')
            
            logsources.append(f"{product}/{service}/{category}")
            
            if product == 'windows':
                windows_rules.append((rule.title, service, category))
            elif product == 'linux':
                linux_rules.append((rule.title, service, category))
            elif product == 'macos':
                macos_rules.append((rule.title, service, category))
                
        except:
            pass
    
    print(f"\nWindows rules: {len(windows_rules)}")
    print(f"Linux rules: {len(linux_rules)}")
    print(f"macOS rules: {len(macos_rules)}")
    print()
    
    # Show Windows Security/Sysmon rules
    print("Windows Security/Sysmon rules (first 20):")
    print("-"*80)
    count = 0
    for title, service, category in windows_rules:
        if 'security' in service.lower() or 'sysmon' in service.lower() or category == 'process_creation':
            print(f"  {title}")
            print(f"    service={service}, category={category}")
            count += 1
            if count >= 20:
                break
    
    if count == 0:
        print("  ❌ NO Windows Security/Sysmon rules enabled!")
        print()
        print("Your EVTX files are Windows Security logs, but you have no matching rules enabled.")
        print()
    
    # Show most common logsources
    print()
    print("Top 20 logsource combinations:")
    print("-"*80)
    for logsource, count in Counter(logsources).most_common(20):
        print(f"  {logsource}: {count} rules")
