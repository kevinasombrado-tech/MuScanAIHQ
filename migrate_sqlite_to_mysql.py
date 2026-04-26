#!/usr/bin/env python3
"""
One-time migration script: Copy all data from SQLite to MySQL.
Run this ONCE after MySQL tables are created via app.py init_db().

Usage:
  python migrate_sqlite_to_mysql.py
  
Environment variables needed:
  DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD (for MySQL target)
  SQLITE_PATH (optional, defaults to ./mitigations.db)
"""

import sqlite3
import os
import sys
from pathlib import Path
import pymysql
from pymysql.cursors import DictCursor

SQLITE_PATH = Path(os.getenv("SQLITE_PATH", "./mitigations.db"))
MYSQL_HOST = os.getenv("DB_HOST", "127.0.0.1")
MYSQL_PORT = int(os.getenv("DB_PORT", "3306"))
MYSQL_DB = os.getenv("DB_NAME", "muscan_admin")
MYSQL_USER = os.getenv("DB_USER", "muscan_app")
MYSQL_PASSWORD = os.getenv("DB_PASSWORD", "")


def open_sqlite():
    """Open SQLite DB with dict-like row access."""
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def open_mysql():
    """Open MySQL DB with dict cursor."""
    conn = pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DB,
        cursorclass=DictCursor,
        charset="utf8mb4",
    )
    return conn


def migrate_table(sqlite_conn, mysql_conn, table_name, columns):
    """
    Migrate rows from SQLite table to MySQL table.
    
    Args:
      sqlite_conn: SQLite connection
      mysql_conn: MySQL connection
      table_name: Name of the table
      columns: List of column names to migrate
    """
    print(f"Migrating {table_name}...", end=" ", flush=True)
    
    # Get all rows from SQLite
    sqlite_cur = sqlite_conn.cursor()
    sqlite_cur.execute(f"SELECT {', '.join(columns)} FROM {table_name}")
    rows = sqlite_cur.fetchall()
    
    if not rows:
        print(f"(empty)")
        return
    
    # Insert into MySQL in batches
    mysql_cur = mysql_conn.cursor()
    placeholders = ", ".join(["%s"] * len(columns))
    insert_sql = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders})"
    
    data = []
    for row in rows:
        data.append(tuple(row[col] for col in columns))
    
    try:
        mysql_cur.executemany(insert_sql, data)
        mysql_conn.commit()
        print(f"({len(rows)} rows)")
    except Exception as e:
        print(f"ERROR: {e}")
        raise


def main():
    """Run the migration."""
    print(f"\n=== SQLite to MySQL Migration ===\n")
    print(f"Source SQLite: {SQLITE_PATH}")
    print(f"Target MySQL: {MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}")
    print()
    
    # Check SQLite exists
    if not SQLITE_PATH.exists():
        print(f"ERROR: SQLite file not found: {SQLITE_PATH}")
        sys.exit(1)
    
    sqlite_conn = open_sqlite()
    mysql_conn = open_mysql()
    
    try:
        # Define tables and columns in dependency order (respecting FK)
        tables = [
            ("users", ["id", "name", "contact_number", "email", "password_hash", "role", "source", "created_at", "updated_at"]),
            ("mitigations", ["id", "severity", "title", "description", "created_at", "updated_at"]),
            ("mitigation_versions", ["severity", "version", "updated_at"]),
            ("mitigation_sent_versions", ["severity", "sent_version", "sent_at", "sent_by"]),
            ("mitigation_send_logs", ["id", "severity", "sent_version", "sent_by", "sent_at"]),
            ("mitigation_sent_items", ["id", "severity", "sent_version", "source_mitigation_id", "title", "description", "sent_at"]),
            ("library_entries", ["id", "title", "body", "image", "created_at", "modified_at"]),
            ("library_version", ["id", "version", "updated_at"]),
            ("library_sent_version", ["id", "sent_version", "sent_at", "sent_by"]),
            ("library_send_logs", ["id", "sent_version", "sent_by", "sent_at"]),
            ("library_sent_items", ["id", "sent_version", "source_library_id", "title", "body", "image", "sent_at"]),
            ("detections", ["id", "user_id", "image_path", "predicted_label", "severity", "confidence", "recommendation_version", "source", "created_at"]),
            ("remarks", ["id", "detection_id", "user_id", "remark", "created_at"]),
            ("activity_logs", ["id", "user_id", "action", "reference_type", "reference_id", "created_at"]),
            ("user_signup_otps", ["id", "contact_number", "otp_hash", "otp_salt", "name", "email", "password_hash", "role", "expires_at", "attempts", "created_at"]),
        ]
        
        for table_name, columns in tables:
            try:
                migrate_table(sqlite_conn, mysql_conn, table_name, columns)
            except sqlite3.OperationalError:
                # Table might not exist in SQLite (skip optional tables)
                print(f"(skipped - table not found in SQLite)")
            except pymysql.MySQLError as e:
                print(f"MySQL error: {e}")
                # Continue with other tables
        
        print(f"\n✓ Migration complete!")
        print(f"\nNext steps:")
        print(f"  1. Verify data integrity by checking row counts:")
        print(f"     SELECT COUNT(*) FROM users;")
        print(f"     SELECT COUNT(*) FROM detections;")
        print(f"  2. Test the API to confirm endpoints still work")
        print(f"  3. Keep SQLite backup until you are confident in the migration")
        
    finally:
        sqlite_conn.close()
        mysql_conn.close()


if __name__ == "__main__":
    main()
