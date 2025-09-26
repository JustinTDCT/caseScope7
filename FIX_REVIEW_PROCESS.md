# caseScope Fix Review Process

## 📋 **MANDATORY CHECKLIST FOR EVERY FIX**

This document establishes the standard process that **MUST** be followed for every bug fix, feature addition, or code change to ensure consistency and prevent deployment issues.

---

## 🔄 **STEP 1: CODE CHANGES**

### **1.1 Primary Changes**
- [ ] Implement the actual fix in the relevant files
- [ ] Add proper error handling and logging
- [ ] Test the change locally (if possible)

### **1.2 Version Management**
- [ ] Update `version.json` with new version number
- [ ] Update description in `version.json` with clear fix summary
- [ ] Update fallback versions in `app.py` (get_current_version functions)

---

## 🔄 **STEP 2: SCRIPT SYNCHRONIZATION**

### **2.1 Install Script (`install.sh`)**
- [ ] Update header version comment (`# caseScope v7.0.XXX Installation Script`)
- [ ] Update version file creation (`echo "7.0.XXX" > /opt/casescope/VERSION`)
- [ ] Update completion log message
- [ ] Check for any new dependencies or system requirements
- [ ] Verify no conflicting configurations

### **2.2 Deploy Script (`deploy.sh`)**
- [ ] Update header version comment (`# caseScope v7.0.XXX Deployment Script`)
- [ ] Update startup log message
- [ ] Update completion log message
- [ ] Check if new templates/static files need copying
- [ ] Verify service configurations are current
- [ ] Check database migration needs

### **2.3 Requirements (`requirements.txt`)**
- [ ] Update header version comment (`# caseScope v7.0.XXX Python Dependencies`)
- [ ] Add any new Python packages needed for the fix
- [ ] Verify version compatibility
- [ ] Check for security updates in existing packages

---

## 🔄 **STEP 3: TESTING & VALIDATION**

### **3.1 Debug Script Updates (`debug.sh`)**
- [ ] Add validation tests for new functionality
- [ ] Update any changed endpoints or services
- [ ] Ensure comprehensive coverage of the fix

### **3.2 Functionality Validation**
- [ ] Verify the fix addresses the original issue
- [ ] Test edge cases and error scenarios
- [ ] Check for any breaking changes
- [ ] Validate user experience flow

---

## 🔄 **STEP 4: DOCUMENTATION & CLEANUP**

### **4.1 Template Verification**
- [ ] Check if new templates are needed
- [ ] Verify existing templates are compatible
- [ ] Update any template references if needed

### **4.2 Support Scripts**
- [ ] Update `emergency_recovery.sh` if applicable
- [ ] Check other utility scripts for version consistency
- [ ] Remove any obsolete files or configurations

### **4.3 Linter & Syntax Checks**
- [ ] Run linter on all modified files
- [ ] Check shell script syntax
- [ ] Verify Python syntax and imports

---

## 🔄 **STEP 5: FINAL VERIFICATION**

### **5.1 Complete Version Synchronization**
Run these commands to verify consistency:
```bash
# Check all version references
grep -r "7.0.XXX" . --include="*.sh" --include="*.py" --include="*.txt" --include="*.json"

# Verify no old version numbers remain
grep -r "7.0.[0-9][0-9][0-9]" . --include="*.sh" --include="*.py" --include="*.txt" --include="*.json"
```

### **5.2 File Completeness Check**
- [ ] All templates exist and are copied by deploy script
- [ ] All static files are present and copied
- [ ] No missing dependencies or imports
- [ ] All referenced files exist

---

## 📊 **VERSION NUMBERING RULES**

| **Change Type** | **Version Increment** | **Example** |
|----------------|----------------------|-------------|
| **Bug Fix** | Patch (X.X.+1) | 7.0.102 → 7.0.103 |
| **Feature Addition** | Minor (X.+1.0) | 7.0.103 → 7.1.0 |
| **Breaking Change** | Major (+1.0.0) | 7.1.0 → 8.0.0 |
| **Security Fix** | Patch with SECURITY note | 7.0.103 → 7.0.104 |

---

## ⚠️ **COMMON PITFALLS TO AVOID**

### **❌ Don't Do This:**
- Update only some version references (causes inconsistency)
- Add new Python packages without updating requirements.txt
- Create new routes without updating debug validation
- Modify database schema without migration plan
- Change service configurations without updating deploy script

### **✅ Always Do This:**
- Update ALL version references consistently
- Test the fix in context of the full application
- Check for downstream effects of the change
- Validate that existing functionality still works
- Document any new configuration requirements

---

## 🚀 **DEPLOYMENT CHECKLIST**

Before declaring a fix complete:
- [ ] All files have consistent version numbers
- [ ] All scripts can run without errors
- [ ] No linter errors in any modified files
- [ ] Debug script validates the new functionality
- [ ] Documentation reflects any new requirements
- [ ] User can successfully deploy and use the fix

---

## 📝 **EXAMPLE: Search Fix v7.0.103**

**Files Modified:**
- `app.py` - Added search route with OpenSearch integration
- `version.json` - Updated to 7.0.103
- `install.sh` - Updated version references
- `deploy.sh` - Updated version references  
- `requirements.txt` - Updated version reference
- `debug.sh` - Added search route validation

**Verification Commands:**
```bash
grep -r "7.0.103" . --include="*.sh" --include="*.py" --include="*.txt" --include="*.json"
grep -r "search" debug.sh
curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/search
```

**Result:** ✅ Consistent, deployable fix with full validation

---

This process ensures that every fix is complete, consistent, and ready for production deployment without missing dependencies or version mismatches.
