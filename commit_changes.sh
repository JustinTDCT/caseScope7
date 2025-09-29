#!/bin/bash

# Quick commit script for caseScope 7.1.24 changes

echo "Committing caseScope 7.1.24 changes..."

git add .
git commit -m "caseScope 7.1.24 - Added comprehensive login debugging and database verification

- Enhanced login route with detailed DEBUG logging for troubleshooting
- Added /debug/database route to check database status without login
- Implemented forced database verification step before starting services  
- Added detailed administrator account confirmation during installation
- Enhanced error handling with stack traces and user enumeration
- Added troubleshooting guidance to installation completion message
- Improved database initialization logic for all install types
- Fixed SQLAlchemy compatibility issues

This version will help diagnose exactly why login is failing by providing
detailed debug output during login attempts and database verification."

echo "Changes committed. To push to GitHub, run:"
echo "git push origin main"
