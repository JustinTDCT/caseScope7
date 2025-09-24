#!/bin/bash

# caseScope Installation Verification Script
# Run this to check if installation completed successfully

echo "=== caseScope Installation Check ==="
echo "Date: $(date)"
echo ""

# Check if directories exist
echo "=== Directory Structure ==="
for dir in "/opt/casescope" "/opt/casescope/logs" "/opt/casescope/rules" "/opt/opensearch"; do
    if [ -d "$dir" ]; then
        echo "✓ $dir exists"
    else
        echo "✗ $dir missing"
    fi
done
echo ""

# Check if key files exist
echo "=== Key Files ==="
for file in "/opt/casescope/logs/install.log" "/opt/opensearch/config/opensearch.yml" "/opt/casescope/rules/sigma-rules" "/opt/casescope/rules/chainsaw-rules"; do
    if [ -e "$file" ]; then
        echo "✓ $file exists"
    else
        echo "✗ $file missing"
    fi
done

if [ -f "/opt/casescope/rules/chainsaw" ]; then
    echo "✓ Chainsaw binary installed"
else
    echo "⚠ Chainsaw binary not found (rules still available)"
fi
echo ""

# Check services
echo "=== Service Status ==="
for service in "opensearch" "redis-server" "nginx"; do
    if systemctl is-enabled --quiet $service 2>/dev/null; then
        if systemctl is-active --quiet $service; then
            echo "✓ $service: enabled and running"
        else
            echo "⚠ $service: enabled but not running"
        fi
    else
        echo "✗ $service: not enabled"
    fi
done
echo ""

# Check if OpenSearch is responding
echo "=== OpenSearch Connectivity ==="
if curl -s -m 5 http://localhost:9200 > /dev/null 2>&1; then
    echo "✓ OpenSearch is responding on port 9200"
    RESPONSE=$(curl -s http://localhost:9200 | jq -r '.version.number' 2>/dev/null || echo "unknown")
    echo "  Version: $RESPONSE"
else
    echo "✗ OpenSearch is not responding on port 9200"
fi
echo ""

# Check if Redis is responding
echo "=== Redis Connectivity ==="
if redis-cli ping > /dev/null 2>&1; then
    echo "✓ Redis is responding"
else
    echo "✗ Redis is not responding"
fi
echo ""

# Check disk space
echo "=== Disk Space ==="
df -h /opt/casescope /opt/opensearch 2>/dev/null | grep -v "Filesystem"
echo ""

# Check memory
echo "=== Memory Usage ==="
free -h
echo ""

# Installation status
echo "=== Installation Status ==="
if [ -f "/opt/casescope/logs/install.log" ]; then
    if grep -q "Installation completed successfully" /opt/casescope/logs/install.log; then
        echo "✓ Installation completed successfully"
    else
        echo "⚠ Installation may not have completed successfully"
        echo "  Check /opt/casescope/logs/install.log for details"
    fi
else
    echo "✗ Installation log not found"
fi

echo ""
echo "=== Next Steps ==="
if systemctl is-active --quiet opensearch && systemctl is-active --quiet redis-server; then
    echo "✓ System ready for application deployment"
    echo "  Run: sudo ./deploy.sh"
else
    echo "⚠ Services need to be started before deployment"
    echo "  Try: sudo systemctl start opensearch redis-server"
    echo "  Then run: sudo ./deploy.sh"
fi
echo ""
