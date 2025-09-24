#!/bin/bash

# OpenSearch Diagnostic Script for caseScope
# Run this if OpenSearch fails to start

echo "=== OpenSearch Diagnostic Script ==="
echo "Date: $(date)"
echo ""

echo "=== System Information ==="
echo "OS: $(lsb_release -d | cut -f2)"
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo ""

echo "=== Memory Information ==="
free -h
echo ""

echo "=== Disk Space ==="
df -h /opt/opensearch
echo ""

echo "=== Java Version ==="
java -version 2>&1
echo ""

echo "=== OpenSearch Service Status ==="
systemctl status opensearch --no-pager
echo ""

echo "=== OpenSearch Configuration ==="
echo "--- opensearch.yml ---"
cat /opt/opensearch/config/opensearch.yml
echo ""
echo "--- jvm.options ---"
cat /opt/opensearch/config/jvm.options
echo ""

echo "=== OpenSearch Logs ==="
if [ -f /opt/opensearch/logs/opensearch.log ]; then
    echo "Last 50 lines of opensearch.log:"
    tail -50 /opt/opensearch/logs/opensearch.log
else
    echo "No opensearch.log file found"
fi
echo ""

echo "=== Process Information ==="
ps aux | grep -i opensearch | grep -v grep
echo ""

echo "=== Network Ports ==="
netstat -tlnp | grep -E "(9200|9300)"
echo ""

echo "=== System Limits ==="
echo "vm.max_map_count: $(sysctl vm.max_map_count)"
echo "ulimit -n: $(ulimit -n)"
echo "ulimit -u: $(ulimit -u)"
echo ""

echo "=== Directory Permissions ==="
ls -la /opt/opensearch/
ls -la /opt/opensearch/data/
ls -la /opt/opensearch/logs/
echo ""

echo "=== Recent System Logs ==="
journalctl -u opensearch --no-pager -n 20
echo ""

echo "=== Diagnostic Complete ==="
echo "If OpenSearch still won't start, try:"
echo "1. sudo systemctl restart opensearch"
echo "2. Check available memory (OpenSearch needs at least 512MB)"
echo "3. Verify Java installation: java -version"
echo "4. Check disk space in /opt/opensearch"
echo "5. Review the logs above for specific error messages"
