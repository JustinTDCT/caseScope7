# Development & Testing Tools

These files were archived on 2025-10-02 as part of the v7.10.3 cleanup.

## Why Archived?

These are **development and debugging tools** that are not part of the core application or used by end users. They were useful during development but are not referenced by the installer or main application.

## Test Scripts (Python)

### `simple_sigma_test.py`
- Quick SIGMA rule testing
- Tests rule matching against sample events
- Development/debugging tool

### `test_one_rule.py`
- Test a single SIGMA rule
- Used for rule development/debugging
- Not part of production workflow

### `test_rerun_rules.py`
- Test the rule re-running functionality
- Development testing tool
- Core functionality is in `tasks.py`

### `test_sigma_direct.py`
- Direct SIGMA rule testing without Chainsaw
- Development/debugging tool
- Not used in production

### `diagnose_sigma_matching.py`
- Diagnose SIGMA rule matching issues
- Debugging tool for rule violations
- Not part of core application

## Debug Scripts (Shell)

### `check_index_fields.sh`
- Check OpenSearch index field mappings
- Debugging tool for indexing issues
- Not referenced by installer

### `check_sigma_logs.sh`
- Parse and analyze SIGMA processing logs
- Debugging tool for rule execution
- Not referenced by installer

### `diagnose_celery.sh`
- Celery worker diagnostics
- Debugging tool for background tasks
- Not referenced by installer

### `commit_changes.sh`
- Git commit helper script
- Development tool
- Not part of application

## Still Available in Root

### User-Facing Utilities (KEPT):
- `enable_quality_rules.py` - Enable high-quality detection rules
- `enable_threat_hunting_rules.py` - Enable Windows threat hunting rules
- `show_enabled_rules.py` - Show which rules are enabled
- `check_enabled_rules.py` - Check enabled rule status

These are **intentionally kept** because users run them to manage SIGMA rules.

## To Restore

If you need these development tools:
```bash
cp archive/dev-tools/*.py .
cp archive/dev-tools/*.sh .
```

But they're not needed for production use.
