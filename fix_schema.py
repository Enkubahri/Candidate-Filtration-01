#!/usr/bin/env python3
"""
Comprehensive database migration script to fix all schema issues.
"""
import sqlite3
import os

def fix_database_schema():
    """Fix database schema to add all missing columns."""
    db_path = 'candidates.db'
    
    if not os.path.exists(db_path):
        print("Database file doesn't exist yet. Nothing to fix.")
        return
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    try:
        # Get the current schema for criteria table
        c.execute("PRAGMA table_info(criteria)")
        columns = [row[1] for row in c.fetchall()]
        print(f"Current criteria table columns: {columns}")
        
        # Add missing columns to criteria table
        columns_to_add = [
            ('min_position_years', 'INTEGER DEFAULT 0'),
            ('qualified_email', 'TEXT DEFAULT "qualified@company.com"'),
            ('unqualified_email', 'TEXT DEFAULT "unqualified@company.com"'),
            ('admin_user_id', 'INTEGER DEFAULT NULL')
        ]
        
        for column_name, column_def in columns_to_add:
            if column_name not in columns:
                try:
                    c.execute(f'ALTER TABLE criteria ADD COLUMN {column_name} {column_def}')
                    print(f"Added {column_name} column to criteria table")
                except sqlite3.OperationalError as e:
                    print(f"Column {column_name} might already exist: {e}")
        
        # Update qualified_email and unqualified_email from notification_email if they exist
        if 'notification_email' in columns:
            c.execute("UPDATE criteria SET qualified_email = notification_email WHERE qualified_email = 'qualified@company.com' OR qualified_email IS NULL")
            c.execute("UPDATE criteria SET unqualified_email = notification_email WHERE unqualified_email = 'unqualified@company.com' OR unqualified_email IS NULL")
            print("Updated email fields from notification_email")
        
        conn.commit()
        print("Schema fix completed successfully!")
        
        # Show final schema
        c.execute("PRAGMA table_info(criteria)")
        columns_after = [(row[1], row[2]) for row in c.fetchall()]
        print(f"Final criteria table schema:")
        for col_name, col_type in columns_after:
            print(f"  - {col_name}: {col_type}")
        
    except Exception as e:
        print(f"Error during schema fix: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    fix_database_schema()
