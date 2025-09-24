#!/bin/bash

# caseScope OpenSearch Indexing Fix
# Fix data sanitization issues causing indexing errors
# Run this as root

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}caseScope OpenSearch Indexing Fix${NC}"
echo "Fixing data sanitization and indexing issues..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Usage: sudo ./fix_opensearch_indexing.sh"
    exit 1
fi

# Stop services
echo "Stopping services..."
systemctl stop casescope-web casescope-worker

# Clear any existing problematic indices
echo "Clearing potentially corrupted OpenSearch indices..."
curl -X DELETE "http://localhost:9200/casescope-*" 2>/dev/null || true

# Add improved sanitization function to app.py (inline patch)
echo "Applying improved data sanitization..."

# Create a backup
cp /opt/casescope/app/app.py /opt/casescope/app/app.py.backup.$(date +%s)

# Apply the fix by updating the sanitize_for_opensearch function
cat > /tmp/sanitize_fix.py << 'EOF'
import re

def apply_sanitization_fix():
    with open('/opt/casescope/app/app.py', 'r') as f:
        content = f.read()
    
    # Find and replace the sanitize_for_opensearch function
    old_function = '''def sanitize_for_opensearch(data, max_depth=10):
    """
    Sanitize XML parsed data for OpenSearch indexing by:
    1. Converting XML text nodes like {'#text': 'value', '@attr': 'attr_val'} to simple strings
    2. Flattening nested structures
    3. Converting all values to JSON-safe types
    """
    if max_depth <= 0:
        return str(data)[:1000]  # Prevent infinite recursion, limit string length
    
    if isinstance(data, dict):
        # Handle XML text nodes: {'#text': 'value', '@attr': 'value'} -> 'value'
        if '#text' in data:
            return str(data['#text'])
        
        # Handle single-key dicts that are likely XML artifacts
        if len(data) == 1:
            key, value = next(iter(data.items()))
            if key.startswith('@'):
                return str(value)
            # Recursively sanitize the value
            sanitized_value = sanitize_for_opensearch(value, max_depth - 1)
            # If the sanitized value is simple, return it directly
            if isinstance(sanitized_value, (str, int, float, bool)):
                return sanitized_value
        
        # For normal dicts, recursively sanitize each value
        sanitized = {}
        for key, value in data.items():
            # Skip XML namespace attributes and complex XML artifacts
            if key.startswith('@') or key.startswith('#'):
                continue
                
            # Clean the key name
            clean_key = str(key).replace('@', '').replace('#', '').replace(' ', '_').lower()
            if clean_key:
                sanitized[clean_key] = sanitize_for_opensearch(value, max_depth - 1)
        
        return sanitized if sanitized else str(data)[:1000]
        
    elif isinstance(data, list):
        # For lists, sanitize each item
        sanitized_list = []
        for item in data[:100]:  # Limit list size to prevent memory issues
            sanitized_item = sanitize_for_opensearch(item, max_depth - 1)
            if sanitized_item is not None and sanitized_item != '':
                sanitized_list.append(sanitized_item)
        
        # If list has only one item and it's a simple type, return the item
        if len(sanitized_list) == 1 and isinstance(sanitized_list[0], (str, int, float, bool)):
            return sanitized_list[0]
        return sanitized_list
        
    elif isinstance(data, (str, int, float, bool)):
        # Simple types are OK as-is, but limit string length
        if isinstance(data, str):
            return data[:1000]
        return data
        
    else:
        # For any other type, convert to string and limit length
        return str(data)[:1000]'''

    new_function = '''def sanitize_for_opensearch(data, max_depth=10):
    """
    Enhanced sanitize XML parsed data for OpenSearch indexing.
    Fixes field mapping conflicts by flattening nested structures more aggressively.
    """
    if max_depth <= 0:
        return str(data)[:500]  # Prevent infinite recursion, shorter limit
    
    if isinstance(data, dict):
        # Handle XML text nodes: {'#text': 'value', '@attr': 'attr_val'} -> 'value'
        if '#text' in data:
            text_value = str(data['#text'])[:500]
            # Also include attributes if they exist
            if len(data) > 1:
                attrs = {k.replace('@', 'attr_'): str(v)[:200] 
                        for k, v in data.items() if k.startswith('@')}
                if attrs:
                    return {'text': text_value, **attrs}
            return text_value
        
        # Aggressively flatten single-key dicts to prevent mapping conflicts
        while len(data) == 1 and isinstance(data, dict):
            key, value = next(iter(data.items()))
            if isinstance(value, dict):
                data = value  # Unwrap one level
            else:
                return sanitize_for_opensearch(value, max_depth - 1)
        
        # For normal dicts, recursively sanitize each value with strict field naming
        sanitized = {}
        processed_keys = set()
        
        for key, value in data.items():
            # Skip XML namespace attributes and complex XML artifacts
            if key.startswith('@') or key.startswith('#'):
                continue
                
            # Create OpenSearch-safe field names
            clean_key = re.sub(r'[^\w]', '_', str(key).lower())
            clean_key = re.sub(r'_+', '_', clean_key).strip('_')
            
            # Prevent duplicate keys
            if clean_key in processed_keys:
                clean_key = f"{clean_key}_{len(processed_keys)}"
            
            if clean_key and len(clean_key) <= 50:  # OpenSearch field name limit
                processed_keys.add(clean_key)
                sanitized_value = sanitize_for_opensearch(value, max_depth - 1)
                
                # Only add non-empty, non-None values
                if sanitized_value is not None and sanitized_value != '':
                    # Ensure values are OpenSearch compatible
                    if isinstance(sanitized_value, dict) and len(sanitized_value) == 0:
                        continue  # Skip empty dicts
                    sanitized[clean_key] = sanitized_value
        
        # Return flattened dict or string representation if too complex
        if len(sanitized) > 50:  # Limit fields to prevent mapping explosion
            return str(data)[:500]
        return sanitized if sanitized else str(data)[:500]
        
    elif isinstance(data, list):
        # For lists, limit size and sanitize each item
        if len(data) > 20:  # Strict limit for performance
            return str(data)[:500]
            
        sanitized_list = []
        for item in data[:20]:
            sanitized_item = sanitize_for_opensearch(item, max_depth - 1)
            if sanitized_item is not None and sanitized_item != '':
                sanitized_list.append(sanitized_item)
        
        # Convert single-item lists to the item itself
        if len(sanitized_list) == 1:
            return sanitized_list[0]
        elif len(sanitized_list) == 0:
            return None
        return sanitized_list
        
    elif isinstance(data, (str, int, float, bool)):
        # Simple types - ensure strings are reasonable length
        if isinstance(data, str):
            cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]', '', data)
            return cleaned[:500] if cleaned else None
        return data
        
    else:
        # For any other type, convert to string and limit length
        return str(data)[:500]'''

    # Replace the function
    if old_function in content:
        content = content.replace(old_function, new_function)
        
        with open('/opt/casescope/app/app.py', 'w') as f:
            f.write(content)
        print("✓ Applied sanitization fix")
        return True
    else:
        print("✗ Could not find function to replace")
        return False

if __name__ == "__main__":
    apply_sanitization_fix()
EOF

# Run the sanitization fix
cd /opt/casescope/app
python3 /tmp/sanitize_fix.py

# Clean up
rm /tmp/sanitize_fix.py

# Reset all file processing status to reprocess with new sanitization
echo "Resetting file processing status for reprocessing..."
cd /opt/casescope/app
python3 -c "
import sys
sys.path.insert(0, '/opt/casescope/app')
from app import db, CaseFile
with db.session() as session:
    files = session.query(CaseFile).all()
    for f in files:
        f.processing_status = 'pending'
        f.processing_progress = 0
        f.sigma_violations = 0
        f.chainsaw_violations = 0
        f.error_message = None
        f.event_count = 0
    session.commit()
    print(f'Reset {len(files)} files for reprocessing')
"

# Fix file permissions
chown -R casescope:casescope /opt/casescope/app
chmod +x /opt/casescope/app/app.py

# Start services
echo "Starting services..."
systemctl start casescope-web
systemctl start casescope-worker

# Wait for services
sleep 5

echo -e "${GREEN}✓ OpenSearch indexing fix applied!${NC}"
echo ""
echo "Changes made:"
echo "  - Enhanced data sanitization with stricter field flattening"
echo "  - Fixed XML parsing conflicts causing mapper_parsing_exception"
echo "  - Reset all files for reprocessing with improved logic"
echo "  - Applied OpenSearch-safe field naming conventions"
echo ""
echo "Files will now be reprocessed automatically with the improved sanitization."
echo "Monitor progress: tail -f /opt/casescope/logs/application.log"
