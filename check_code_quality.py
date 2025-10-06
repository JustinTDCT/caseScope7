#!/usr/bin/env python3
"""
caseScope Code Quality Checker
Validates Python code structure and identifies potential issues
"""
import ast
import sys
from typing import List, Tuple

def check_syntax(filename: str) -> Tuple[bool, str]:
    """Check if file has valid Python syntax"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            ast.parse(f.read(), filename=filename)
        return True, "✅ Valid syntax"
    except SyntaxError as e:
        return False, f"❌ Syntax error at line {e.lineno}: {e.msg}"
    except Exception as e:
        return False, f"❌ Error: {e}"

def check_indentation(filename: str) -> List[str]:
    """Check for indentation anti-patterns"""
    issues = []
    
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    for i, line in enumerate(lines, 1):
        # Skip empty lines and comments
        if not line.strip() or line.strip().startswith('#'):
            continue
        
        # Check for mixed tabs and spaces (actual problem)
        leading = line[:len(line) - len(line.lstrip())]
        if '\t' in leading and ' ' in leading:
            issues.append(f"Line {i}: Mixed tabs and spaces in indentation")
    
    return issues

def analyze_structure(filename: str) -> List[str]:
    """Analyze code structure for complexity issues"""
    warnings = []
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        tree = ast.parse(content, filename=filename)
    except:
        return warnings
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            func_name = node.name
            func_lineno = node.lineno
            
            # Calculate function size
            body_size = node.end_lineno - node.lineno if hasattr(node, 'end_lineno') else 0
            
            # Warn on very large functions
            if body_size > 400:
                warnings.append(
                    f"⚠️  Function '{func_name}' is {body_size} lines (line {func_lineno}) - "
                    f"refactor recommended to reduce indentation complexity"
                )
            
            # Check nesting depth
            max_depth = 0
            def get_depth(n, depth=0):
                nonlocal max_depth
                max_depth = max(max_depth, depth)
                for child in ast.iter_child_nodes(n):
                    if isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                        get_depth(child, depth + 1)
                    else:
                        get_depth(child, depth)
            
            get_depth(node)
            if max_depth > 7:
                warnings.append(
                    f"⚠️  Function '{func_name}' has nesting depth {max_depth} (line {func_lineno}) - "
                    f"deep nesting increases indentation error risk"
                )
    
    return warnings

def main():
    files_to_check = [
        'main.py',
        'tasks.py', 
        'tasks_queue.py',
        'iris_sync.py',
        'iris_client.py',
        'celery_app.py',
        'theme.py',
        'wsgi.py'
    ]
    
    print("="*80)
    print("caseScope Code Quality Check")
    print("="*80)
    
    total_errors = 0
    total_warnings = 0
    
    for filename in files_to_check:
        print(f"\n📄 {filename}")
        print("-" * 80)
        
        # Check syntax
        syntax_ok, syntax_msg = check_syntax(filename)
        print(f"  Syntax: {syntax_msg}")
        if not syntax_ok:
            total_errors += 1
            continue
        
        # Check indentation
        indent_issues = check_indentation(filename)
        if indent_issues:
            print(f"  ❌ Indentation: {len(indent_issues)} issues found")
            for issue in indent_issues[:5]:
                print(f"     {issue}")
            if len(indent_issues) > 5:
                print(f"     ... and {len(indent_issues) - 5} more")
            total_errors += len(indent_issues)
        else:
            print(f"  ✅ Indentation: No issues")
        
        # Check structure
        structure_warnings = analyze_structure(filename)
        if structure_warnings:
            print(f"  ⚠️  Structure: {len(structure_warnings)} warnings")
            for warning in structure_warnings:
                print(f"     {warning}")
            total_warnings += len(structure_warnings)
        else:
            print(f"  ✅ Structure: No warnings")
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    if total_errors > 0:
        print(f"❌ {total_errors} ERRORS found - must be fixed")
        sys.exit(1)
    elif total_warnings > 0:
        print(f"⚠️  {total_warnings} warnings - code works but refactoring recommended")
        print("\nWARNINGS indicate:")
        print("  • Functions >400 lines are prone to indentation errors")
        print("  • Nesting >7 levels makes code hard to maintain")
        print("  • Consider breaking large functions into smaller ones")
        sys.exit(0)
    else:
        print("✅ All checks passed - code quality is good")
        sys.exit(0)

if __name__ == '__main__':
    main()

