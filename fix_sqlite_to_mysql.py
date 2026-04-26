#!/usr/bin/env python3
"""
Auto-fix remaining SQLite syntax in app.py to MySQL.
This script converts remaining ? placeholders to %s and fixes IntegrityError references.

Run this ONCE:
  python fix_sqlite_to_mysql.py
"""

import re
from pathlib import Path

APP_FILE = Path(__file__).parent / "app.py"

def fix_file():
    """Fix remaining SQLite syntax."""
    content = APP_FILE.read_text()
    original = content
    
    # Fix remaining ? placeholders in SQL strings
    # This is careful to only fix SQL parameter placeholders
    content = re.sub(
        r'(SELECT|INSERT|UPDATE|DELETE)[^"]*"[^"]*\?',
        lambda m: m.group(0).replace('?', '%s'),
        content,
        flags=re.IGNORECASE
    )
    
    # Also fix? in execute() calls within SQL strings
    content = re.sub(r'\(\?\s*,', r'(%s ,', content)
    
    # Fix sqlite3.IntegrityError -> pymysql.err.IntegrityError
    content = content.replace('sqlite3.IntegrityError', 'pymysql.err.IntegrityError')
    
    # Fix remaining CURRENT_TIMESTAMP to NOW()
    content = content.replace('CURRENT_TIMESTAMP', 'NOW()')
    
    # Write back
    APP_FILE.write_text(content)
    
    if content != original:
        print("✓ Fixed remaining SQLite syntax in app.py")
        return True
    else:
        print("No changes needed - file already updated")
        return False

if __name__ == "__main__":
    fix_file()
