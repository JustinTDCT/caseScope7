#!/bin/bash
# Check what's in the local uploads folder

echo "=========================================="
echo "LOCAL UPLOADS FOLDER DIAGNOSTIC"
echo "=========================================="

LOCAL_FOLDER="/opt/casescope/local_uploads/2"

if [ ! -d "$LOCAL_FOLDER" ]; then
    echo "❌ Folder does not exist: $LOCAL_FOLDER"
    exit 1
fi

echo ""
echo "📁 Folder: $LOCAL_FOLDER"
echo ""

# Count files by type
ZIP_COUNT=$(find "$LOCAL_FOLDER" -type f -name "*.zip" 2>/dev/null | wc -l)
EVTX_COUNT=$(find "$LOCAL_FOLDER" -type f -name "*.evtx" 2>/dev/null | wc -l)
JSON_COUNT=$(find "$LOCAL_FOLDER" -type f -name "*.json" -o -name "*.ndjson" 2>/dev/null | wc -l)
TOTAL_COUNT=$(find "$LOCAL_FOLDER" -type f 2>/dev/null | wc -l)

echo "📊 File counts:"
echo "   ZIP files:   $ZIP_COUNT"
echo "   EVTX files:  $EVTX_COUNT"
echo "   JSON files:  $JSON_COUNT"
echo "   Total files: $TOTAL_COUNT"
echo ""

if [ $TOTAL_COUNT -gt 0 ]; then
    echo "⚠️  Files found in local uploads folder!"
    echo "   These will be processed again if you click 'Process Local Uploads'"
    echo ""
    echo "First 10 files:"
    find "$LOCAL_FOLDER" -type f 2>/dev/null | head -10
    echo ""
    echo "To clean up:"
    echo "   rm -rf $LOCAL_FOLDER/*"
else
    echo "✅ Local uploads folder is empty (correct state after processing)"
fi

echo "=========================================="

