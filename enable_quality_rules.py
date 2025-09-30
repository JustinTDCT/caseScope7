#!/usr/bin/env python3
"""
Enable high-quality SIGMA rules based on severity and category
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from main import app, db, SigmaRule

print("="*80)
print("ENABLING HIGH-QUALITY SIGMA RULES")
print("="*80)
print()

with app.app_context():
    # Strategy: Enable rules that are:
    # 1. High or Critical severity
    # 2. Windows-related categories
    # 3. Stable or test status (not experimental)
    
    print("Finding high-quality detection rules...")
    print()
    
    # Get all rules
    all_rules = SigmaRule.query.filter_by(is_builtin=False).all()
    
    # Categories relevant to Windows Security/System/Defender logs
    windows_categories = [
        'process_creation', 'network_connection', 'registry', 'file_event',
        'security', 'sysmon', 'powershell', 'defender', 'windows',
        'authentication', 'credential_access', 'lateral_movement'
    ]
    
    enabled_count = 0
    candidates = []
    
    for rule in all_rules:
        if rule.is_enabled:
            continue  # Already enabled
        
        # Criteria for auto-enable:
        # - High or Critical level
        # - OR Windows-related category
        # - AND not experimental (experimental rules can be noisy)
        
        level = (rule.level or 'medium').lower()
        category = (rule.category or '').lower()
        status = (rule.status or 'stable').lower()
        
        should_enable = False
        reason = ""
        
        # High/Critical rules are valuable
        if level in ['high', 'critical']:
            should_enable = True
            reason = f"Level: {level}"
        
        # Windows-related medium rules
        elif level == 'medium' and any(cat in category for cat in windows_categories):
            should_enable = True
            reason = f"Windows category: {category}"
        
        # Skip experimental unless high/critical
        if status == 'experimental' and level not in ['high', 'critical']:
            should_enable = False
        
        if should_enable:
            candidates.append((rule, reason))
    
    print(f"Found {len(candidates)} rules to enable")
    print()
    
    # Show breakdown
    by_level = {}
    for rule, reason in candidates:
        level = rule.level or 'unknown'
        by_level[level] = by_level.get(level, 0) + 1
    
    print("Breakdown by severity:")
    for level in ['critical', 'high', 'medium', 'low']:
        count = by_level.get(level, 0)
        if count > 0:
            print(f"  {level.upper()}: {count} rules")
    print()
    
    # Confirm with user
    print(f"This will enable {len(candidates)} additional rules (currently 5 enabled)")
    print(f"Total enabled after: {5 + len(candidates)} rules")
    print()
    
    # Show sample
    print("Sample rules that will be enabled:")
    for rule, reason in candidates[:10]:
        print(f"  ✓ {rule.title[:60]} ({rule.level}) - {reason}")
    if len(candidates) > 10:
        print(f"  ... and {len(candidates) - 10} more")
    print()
    
    # Enable them
    print("Enabling rules...")
    for rule, reason in candidates:
        rule.is_enabled = True
        enabled_count += 1
        if enabled_count % 100 == 0:
            print(f"  Enabled {enabled_count}/{len(candidates)}...")
    
    db.session.commit()
    
    print()
    print("="*80)
    print(f"SUCCESS: Enabled {enabled_count} new rules")
    print(f"Total enabled rules: {SigmaRule.query.filter_by(is_enabled=True).count()}")
    print("="*80)
    print()
    print("Now click 'Re-run Rules' in the UI to process them!")
