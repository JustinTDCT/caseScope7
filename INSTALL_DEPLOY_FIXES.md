# Install & Deploy Script Fixes Summary

## Version: 7.0.131

### ✅ CONFIRMED FIXES INCLUDED:

#### **install.sh:**
1. **Version Updated**: Now shows v7.0.131 
2. **VM Max Map Count**: Prevents duplication with proper checking
3. **Correct Mapping URL**: Uses `sigma-event-logs-all.yml` (not process-creation)
4. **Python Dependencies**: Framework for requirements.txt installation
5. **Service Configuration**: Proper systemd services setup
6. **OpenSearch Handling**: Preserve/install options for existing installations
7. **Fallback Versions**: Updated to 7.0.131

#### **deploy.sh:**
1. **Version Updated**: Now shows v7.0.131
2. **Requirements.txt**: Copies and installs all Python dependencies
3. **Database Permissions**: Comprehensive database file permission handling
4. **Import Testing**: Tests all critical imports before deployment
5. **Service Management**: Proper service restart and verification
6. **OpenSearch Integration**: Respects install script OpenSearch decisions
7. **Comprehensive Diagnostics**: Health checks for all components

#### **requirements.txt:**
1. **EVTX Package**: Fixed to use `python-evtx==0.8.2` (not just `evtx`)
2. **All Dependencies**: Includes bcrypt, APScheduler, opensearch-py, etc.
3. **Version Pinning**: All packages have specific versions for stability

### 🎯 KEY IMPROVEMENTS:

#### **Database Issues Fixed:**
- Proper file permissions (664)
- Correct ownership (casescope:casescope)
- Write permission verification
- SQLite access testing

#### **Python Dependencies Fixed:**
- All required packages included
- Correct package names
- Version compatibility ensured
- Import testing after installation

#### **OpenSearch Integration Fixed:**
- Correct mapping file URL
- No nested query errors (handled in app.py)
- Proper configuration files
- Service integration

#### **System Configuration Fixed:**
- VM memory mapping for OpenSearch
- User permissions and ownership
- Service file configurations
- Log file management

### 🚀 DEPLOYMENT READINESS:

Both scripts now contain:
- ✅ All recent bug fixes
- ✅ Updated version numbers
- ✅ Correct dependencies
- ✅ Proper error handling
- ✅ Comprehensive logging
- ✅ Health verification

### 📝 INSTALLATION PROCESS:

1. **Run**: `sudo ./install.sh`
   - Sets up system dependencies
   - Installs OpenSearch, Chainsaw, Python
   - Creates users and services

2. **Run**: `sudo ./deploy.sh`
   - Copies application files
   - Installs Python requirements
   - Initializes database
   - Starts services

Both scripts work together to create a fully functional caseScope v7.0.131 installation with all recent fixes applied.
