#!/usr/bin/env python3
"""
Remove duplicate files from Case 2
Keeps the FIRST record of each (hash + filename) pair, deletes the rest
"""

import sqlite3
import os
import sys

DB_PATH = '/opt/casescope/data/casescope.db'
CASE_ID = 2

print("="*80)
print("DUPLICATE FILE CLEANUP")
print("="*80)

response = input(f"\n⚠️  This will DELETE duplicate files from Case {CASE_ID}!\n    Type 'YES' to continue: ")
if response != 'YES':
    print("Cancelled.")
    sys.exit(0)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Find all duplicates (same hash + filename)
cursor.execute("""
    SELECT file_hash, original_filename, COUNT(*) as cnt
    FROM case_file
    WHERE case_id = ? AND file_hash IS NOT NULL
    GROUP BY file_hash, original_filename
    HAVING cnt > 1
""", (CASE_ID,))

duplicates = cursor.fetchall()

if not duplicates:
    print("\n✓ No duplicates found!")
    conn.close()
    sys.exit(0)

print(f"\nFound {len(duplicates)} sets of duplicate files")

total_to_delete = 0
for file_hash, filename, count in duplicates:
    total_to_delete += (count - 1)  # Keep first, delete rest

print(f"Will delete {total_to_delete} duplicate file records")

deleted_count = 0
kept_count = 0

for file_hash, filename, count in duplicates:
    # Get all IDs for this hash+filename combo
    cursor.execute("""
        SELECT id, uploaded_at, event_count, is_hidden
        FROM case_file
        WHERE case_id = ? AND file_hash = ? AND original_filename = ?
        ORDER BY id ASC
    """, (CASE_ID, file_hash, filename))
    
    records = cursor.fetchall()
    
    # Keep first, delete rest
    keep_id = records[0][0]
    keep_uploaded = records[0][1]
    keep_events = records[0][2]
    keep_hidden = records[0][3]
    
    print(f"\n{filename} (hash: {file_hash[:16]}...)")
    print(f"  KEEP: ID={keep_id}, uploaded={keep_uploaded}, events={keep_events}, hidden={keep_hidden}")
    kept_count += 1
    
    for record in records[1:]:
        delete_id = record[0]
        delete_uploaded = record[1]
        delete_events = record[2]
        delete_hidden = record[3]
        
        print(f"  DELETE: ID={delete_id}, uploaded={delete_uploaded}, events={delete_events}, hidden={delete_hidden}")
        
        # Delete from database
        cursor.execute("DELETE FROM case_file WHERE id = ?", (delete_id,))
        
        # Delete physical file if it exists
        cursor.execute("SELECT file_path FROM case_file WHERE id = ?", (keep_id,))
        result = cursor.fetchone()
        if result:
            file_path = result[0]
            if os.path.exists(file_path):
                # Only delete if there's another copy
                duplicate_path = file_path.replace(f"_{keep_id}_", f"_{delete_id}_")
                if os.path.exists(duplicate_path):
                    os.remove(duplicate_path)
                    print(f"    Deleted physical file: {duplicate_path}")
        
        deleted_count += 1

conn.commit()

print("\n" + "="*80)
print(f"CLEANUP COMPLETE")
print(f"  Kept: {kept_count} unique files")
print(f"  Deleted: {deleted_count} duplicate records")
print("="*80)

# Show new counts
cursor.execute("SELECT COUNT(*) FROM case_file WHERE case_id = ?", (CASE_ID,))
total = cursor.fetchone()[0]
print(f"\nNew total file count: {total}")

cursor.execute("SELECT COUNT(*) FROM case_file WHERE case_id = ? AND is_hidden = 1", (CASE_ID,))
hidden = cursor.fetchone()[0]
print(f"Hidden files: {hidden}")

cursor.execute("SELECT COUNT(*) FROM case_file WHERE case_id = ? AND indexing_status = 'Completed'", (CASE_ID,))
completed = cursor.fetchone()[0]
print(f"Completed files: {completed}")

print("\n⚠️  IMPORTANT: You should now:")
print("  1. Restart the worker: sudo systemctl restart casescope-worker")
print("  2. Refresh the UI to see updated counts")
print("="*80 + "\n")

conn.close()

