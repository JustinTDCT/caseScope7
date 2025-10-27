#!/usr/bin/env python3
"""
Diagnostic script to understand file count discrepancy
"""

import sqlite3

DB_PATH = '/opt/casescope/data/casescope.db'

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

print("="*80)
print("FILE COUNT DIAGNOSTIC")
print("="*80)

# Check Case 2
cursor.execute("SELECT id, name FROM 'case' WHERE id = 2")
case = cursor.fetchone()
if case:
    print(f"\nCase {case[0]}: {case[1]}")
else:
    print("\nCase 2 not found!")
    exit(1)

# Total files
cursor.execute("SELECT COUNT(*) FROM case_file WHERE case_id = 2")
total = cursor.fetchone()[0]
print(f"\n📁 Total CaseFile records: {total}")

# Breakdown by status
cursor.execute("""
    SELECT indexing_status, COUNT(*) 
    FROM case_file 
    WHERE case_id = 2 
    GROUP BY indexing_status
    ORDER BY COUNT(*) DESC
""")
print("\n📊 By Status:")
for status, count in cursor.fetchall():
    print(f"   {status}: {count}")

# Breakdown by upload type
cursor.execute("""
    SELECT upload_type, COUNT(*) 
    FROM case_file 
    WHERE case_id = 2 
    GROUP BY upload_type
""")
print("\n📤 By Upload Type:")
for upload_type, count in cursor.fetchall():
    ut = upload_type or '(null)'
    print(f"   {ut}: {count}")

# Breakdown by upload time (grouped by hour)
cursor.execute("""
    SELECT 
        strftime('%Y-%m-%d %H:00', uploaded_at) as hour,
        COUNT(*) as count
    FROM case_file 
    WHERE case_id = 2
    GROUP BY hour
    ORDER BY hour DESC
    LIMIT 10
""")
print("\n⏰ By Upload Time (last 10 hours):")
for hour, count in cursor.fetchall():
    print(f"   {hour}: {count} files")

# Hidden files
cursor.execute("SELECT COUNT(*) FROM case_file WHERE case_id = 2 AND is_hidden = 1")
hidden = cursor.fetchone()[0]
print(f"\n🙈 Hidden files: {hidden}")

# Failed files
cursor.execute("SELECT COUNT(*) FROM case_file WHERE case_id = 2 AND indexing_status = 'Failed'")
failed = cursor.fetchone()[0]
print(f"\n❌ Failed files: {failed}")

# Duplicates
cursor.execute("""
    SELECT file_hash, original_filename, COUNT(*) as cnt
    FROM case_file
    WHERE case_id = 2
    GROUP BY file_hash, original_filename
    HAVING cnt > 1
    LIMIT 10
""")
dupes = cursor.fetchall()
if dupes:
    print(f"\n⚠️  DUPLICATE FILES (hash + filename):")
    for file_hash, filename, count in dupes:
        print(f"   {filename}: {count} copies (hash: {file_hash[:16]}...)")
else:
    print(f"\n✓ No duplicate files found")

# Files with same hash but different names
cursor.execute("""
    SELECT file_hash, COUNT(DISTINCT original_filename) as name_count, COUNT(*) as total_count
    FROM case_file
    WHERE case_id = 2 AND file_hash IS NOT NULL
    GROUP BY file_hash
    HAVING name_count > 1
    LIMIT 10
""")
same_hash = cursor.fetchall()
if same_hash:
    print(f"\n🔄 SAME HASH, DIFFERENT FILENAMES (valid - different systems):")
    for file_hash, name_count, total_count in same_hash:
        print(f"   Hash {file_hash[:16]}...: {name_count} different names, {total_count} total files")
        # Show the filenames
        cursor.execute("""
            SELECT original_filename FROM case_file
            WHERE case_id = 2 AND file_hash = ?
            LIMIT 5
        """, (file_hash,))
        for (fname,) in cursor.fetchall():
            print(f"      - {fname}")

print("\n" + "="*80)

conn.close()

