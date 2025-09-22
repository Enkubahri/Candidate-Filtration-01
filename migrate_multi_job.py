#!/usr/bin/env python3
"""
Database migration script to update schema for multi-job functionality.
Adds job_status column and other necessary fields for the enhanced admin system.
"""
import sqlite3
import os

def migrate_database():
    """Migrate database to support multi-job functionality."""
    db_path = 'candidates.db'
    
    if not os.path.exists(db_path):
        print("Database file doesn't exist yet. Nothing to migrate.")
        return
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    try:
        # Get the current schema
        c.execute("PRAGMA table_info(criteria)")
        columns = [row[1] for row in c.fetchall()]
        print(f"Current criteria table columns: {columns}")
        
        # Add job_status column if it doesn't exist
        if 'job_status' not in columns:
            try:
                c.execute('ALTER TABLE criteria ADD COLUMN job_status TEXT DEFAULT "open"')
                print("Added job_status column to criteria table")
            except sqlite3.OperationalError as e:
                print(f"Job_status column might already exist: {e}")
        
        # Add position_title if it doesn't exist
        if 'position_title' not in columns:
            try:
                c.execute('ALTER TABLE criteria ADD COLUMN position_title TEXT DEFAULT "Legacy Position"')
                print("Added position_title column to criteria table")
            except sqlite3.OperationalError as e:
                print(f"Position_title column might already exist: {e}")
        
        # Add expected_positions if it doesn't exist
        if 'expected_positions' not in columns:
            try:
                c.execute('ALTER TABLE criteria ADD COLUMN expected_positions TEXT DEFAULT ""')
                print("Added expected_positions column to criteria table")
            except sqlite3.OperationalError as e:
                print(f"Expected_positions column might already exist: {e}")
        
        # Add min_position_years if it doesn't exist
        if 'min_position_years' not in columns:
            try:
                c.execute('ALTER TABLE criteria ADD COLUMN min_position_years INTEGER DEFAULT 0')
                print("Added min_position_years column to criteria table")
            except sqlite3.OperationalError as e:
                print(f"Min_position_years column might already exist: {e}")
        
        # Add qualified_email if it doesn't exist
        if 'qualified_email' not in columns:
            try:
                c.execute('ALTER TABLE criteria ADD COLUMN qualified_email TEXT DEFAULT ""')
                print("Added qualified_email column to criteria table")
            except sqlite3.OperationalError as e:
                print(f"Qualified_email column might already exist: {e}")
        
        # Add unqualified_email if it doesn't exist
        if 'unqualified_email' not in columns:
            try:
                c.execute('ALTER TABLE criteria ADD COLUMN unqualified_email TEXT DEFAULT ""')
                print("Added unqualified_email column to criteria table")
            except sqlite3.OperationalError as e:
                print(f"Unqualified_email column might already exist: {e}")
        
        # Add admin_user_id if it doesn't exist
        if 'admin_user_id' not in columns:
            try:
                c.execute('ALTER TABLE criteria ADD COLUMN admin_user_id INTEGER')
                print("Added admin_user_id column to criteria table")
            except sqlite3.OperationalError as e:
                print(f"Admin_user_id column might already exist: {e}")
        
        # Update existing records to have job_status = "open" where is_active = 1
        if 'job_status' in columns or 'job_status' not in columns:  # Just added or already exists
            c.execute("UPDATE criteria SET job_status = 'open' WHERE is_active = 1")
            c.execute("UPDATE criteria SET job_status = 'closed' WHERE is_active = 0")
            updated_rows = c.rowcount
            print(f"Updated job_status for {updated_rows} existing records")
        
        conn.commit()
        print("Migration completed successfully!")
        
        # Show final schema
        c.execute("PRAGMA table_info(criteria)")
        columns_after = [row[1] for row in c.fetchall()]
        print(f"Final criteria table columns: {columns_after}")
        
        # Show sample data
        c.execute("SELECT id, position_title, job_status, is_active FROM criteria LIMIT 3")
        sample_data = c.fetchall()
        print(f"\nSample data:")
        for row in sample_data:
            print(f"  ID: {row[0]}, Position: {row[1]}, Status: {row[2]}, Active: {row[3]}")
        
    except Exception as e:
        print(f"Error during migration: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database()
