#!/bin/bash

# caseScope Nightly Update Script
# Run this daily to update Sigma rules, Chainsaw rules, and mappings

set -e

echo "=================================================="
echo "caseScope Nightly Update Script"
echo "$(date): Starting nightly update..."
echo "=================================================="

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting nightly update process..."

# 1. UPDATE SIGMA RULES
log "=== UPDATING SIGMA RULES ==="
SIGMA_DIR="/opt/casescope/rules/sigma-rules"

if [ -d "$SIGMA_DIR" ]; then
    log "Updating existing Sigma rules repository..."
    cd "$SIGMA_DIR"
    git pull origin master 2>/dev/null || git pull origin main 2>/dev/null || log "Sigma rules update failed"
    sigma_count=$(find . -name "*.yml" | wc -l)
    log "Sigma rules updated: $sigma_count total rules"
else
    log "Sigma rules directory not found - skipping Sigma update"
fi

# 2. UPDATE CHAINSAW RULES  
log "=== UPDATING CHAINSAW RULES ==="
CHAINSAW_RULES_DIR="/opt/casescope/rules/chainsaw-rules"

if [ -d "$CHAINSAW_RULES_DIR" ]; then
    log "Updating existing Chainsaw rules repository..."
    cd "$CHAINSAW_RULES_DIR"
    git pull origin master 2>/dev/null || git pull origin main 2>/dev/null || log "Chainsaw rules update failed"
    chainsaw_count=$(find rules -name "*.yml" 2>/dev/null | wc -l)
    log "Chainsaw rules updated: $chainsaw_count total rules"
else
    log "Chainsaw rules directory not found - skipping Chainsaw rules update"
fi

# 3. UPDATE OFFICIAL CHAINSAW MAPPINGS (NEW!)
log "=== UPDATING OFFICIAL CHAINSAW MAPPINGS ==="
MAPPINGS_DIR="/usr/local/bin/mappings"
MAPPING_FILE="$MAPPINGS_DIR/sigma-event-logs-all.yml"

log "Downloading latest official Chainsaw mappings from WithSecure Labs..."
mkdir -p "$MAPPINGS_DIR"

# Download the official mappings directly from GitHub
if curl -L "https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/mappings/sigma-event-logs-all.yml" -o "$MAPPING_FILE" 2>/dev/null; then
    log "✅ Official Chainsaw mappings downloaded successfully"
    
    # Download other mapping files too
    curl -L "https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/mappings/sigma-event-logs-process-creation.yml" -o "$MAPPINGS_DIR/sigma-event-logs-process-creation.yml" 2>/dev/null || true
    curl -L "https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/mappings/sigma-event-logs-network-connection.yml" -o "$MAPPINGS_DIR/sigma-event-logs-network-connection.yml" 2>/dev/null || true
    
    # Verify the main mapping file
    if grep -q "groups:" "$MAPPING_FILE" 2>/dev/null; then
        log "✅ Mapping file contains required 'groups' structure"
    else
        log "⚠️ Downloaded mapping may be invalid format"
    fi
else
    log "❌ Failed to download official mappings - trying fallback method..."
    
    # Fallback: Clone repo and extract mappings
    cd /tmp
    rm -rf chainsaw-mappings
    if git clone --depth 1 https://github.com/WithSecureLabs/chainsaw.git chainsaw-mappings 2>/dev/null; then
        if [ -d "chainsaw-mappings/mappings" ]; then
            cp chainsaw-mappings/mappings/*.yml "$MAPPINGS_DIR/" 2>/dev/null || true
            log "✅ Mappings copied from git clone"
        fi
        rm -rf chainsaw-mappings
    else
        log "❌ All mapping download methods failed"
    fi
fi

# 4. UPDATE STATISTICS
log "=== UPDATE STATISTICS ==="
cd /opt/casescope/rules

# Count all rules
sigma_total=$(find sigma-rules -name "*.yml" 2>/dev/null | wc -l || echo "0")
chainsaw_total=$(find chainsaw-rules/rules -name "*.yml" 2>/dev/null | wc -l || echo "0")
mappings_total=$(find /usr/local/bin/mappings -name "*.yml" 2>/dev/null | wc -l || echo "0")

log "=== NIGHTLY UPDATE SUMMARY ==="
log "✅ Sigma Rules: $sigma_total"
log "✅ Chainsaw Rules: $chainsaw_total" 
log "✅ Official Mappings: $mappings_total"

# 5. RESTART SERVICES TO PICK UP NEW RULES
log "=== RESTARTING SERVICES ==="
log "Restarting caseScope services to pick up new rules..."
systemctl restart casescope-worker 2>/dev/null || log "Failed to restart worker service"
systemctl restart casescope-web 2>/dev/null || log "Failed to restart web service"

log "🌙 Nightly update complete!"

echo "=================================================="
echo "NIGHTLY UPDATE COMPLETE"
echo "  Sigma Rules:     $sigma_total"
echo "  Chainsaw Rules:  $chainsaw_total"
echo "  Official Maps:   $mappings_total"
echo "  Next Update:     $(date -d '+1 day' '+%Y-%m-%d 02:00')"
echo "=================================================="
