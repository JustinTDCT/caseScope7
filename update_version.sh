#!/bin/bash

# caseScope Version Update Script
# Usage: ./update_version.sh <new_version> [description]

if [ $# -lt 1 ]; then
    echo "Usage: $0 <new_version> [description]"
    echo "Example: $0 7.1.0 'Added new features'"
    echo ""
    echo "Current version:"
    python3 version_utils.py info
    exit 1
fi

NEW_VERSION="$1"
DESCRIPTION="${2:-Version update}"

echo "Updating caseScope version to $NEW_VERSION..."

# Update version in JSON file
python3 version_utils.py set "$NEW_VERSION" "$DESCRIPTION"

if [ $? -eq 0 ]; then
    echo "✅ Version updated successfully!"
    echo ""
    echo "New version info:"
    python3 version_utils.py info
    echo ""
    echo "📝 Next steps:"
    echo "1. Commit the version.json change to Git"
    echo "2. Run deployment script to apply changes"
    echo "3. The version will appear automatically in all templates"
else
    echo "❌ Failed to update version"
    exit 1
fi
