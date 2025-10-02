# Archived v7.0 Theme Files

These files were archived on 2025-10-02 as part of the v7.10.2 cleanup.

## Why Archived?

caseScope 7.1+ uses a **render-based architecture** (not template-based):
- HTML is generated directly in `main.py` using f-strings
- CSS is provided by `theme.py` via `get_theme_css()`
- NO `render_template()` calls
- NO static CSS loading

## Contents

### `style.css` (1766 lines)
- v7.0 theme with CSS variables
- Loaded by `base.html` template
- **Never loaded** in render-based system
- Different color scheme than current theme

### `main.js` (750 lines)
- Theme switching functionality
- File upload handlers
- Search functionality
- Debug console
- References CSS variables from `style.css`
- **Not needed** in current render-based system

### `templates/` (15 HTML files)
- Jinja2 templates from v7.0
- Use template inheritance (`{% extends %}`)
- Reference `style.css` and `main.js`
- **Not used** in render-based system

## Current Architecture (v7.10+)

```
main.py (render functions)
    └── theme.py (get_theme_css())
        └── Inline <style> in HTML
```

**No external CSS or templates!**

## If You Need These Files

They're here for reference. To restore:
```bash
mv archive/v7.0-orphaned/style.css static/css/
mv archive/v7.0-orphaned/main.js static/js/
mv archive/v7.0-orphaned/templates ./
```

But you'd need to refactor `main.py` to use `render_template()` instead of direct rendering.
