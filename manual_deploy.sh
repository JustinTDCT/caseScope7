#!/bin/bash

# Manual deployment script to copy updated files
echo "Copying updated files to deployment location..."

# Copy the updated app.py
sudo cp /Users/jdube/caseScope7_cursor/app.py /opt/casescope/app.py
echo "✓ Copied app.py"

# Copy the updated search template
sudo cp /Users/jdube/caseScope7_cursor/templates/search_simple.html /opt/casescope/templates/search_simple.html
echo "✓ Copied search_simple.html"

# Copy version file
sudo cp /Users/jdube/caseScope7_cursor/version.json /opt/casescope/version.json
echo "✓ Copied version.json"

# Set proper ownership
sudo chown -R casescope:casescope /opt/casescope/

# Restart the web service
echo "Restarting caseScope web service..."
sudo systemctl restart casescope-web

echo "✅ Manual deployment complete!"
echo "The search interface should now work properly."
