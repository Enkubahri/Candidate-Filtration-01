#!/usr/bin/env python3
"""
Database migration script to add missing columns to criteria table.
This script will safely add the new columns without losing existing data.
"""
import sqlite3
import os

def migrate_database():
    """Migrate database to add missing columns."""
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
        
        # Migrate data from required_skills to expected_positions if needed
        if 'required_skills' in columns and 'expected_positions' in columns:
            c.execute("UPDATE criteria SET expected_positions = required_skills WHERE expected_positions = '' OR expected_positions IS NULL")
            rows_updated = c.rowcount
            if rows_updated > 0:
                print(f"Migrated data from required_skills to expected_positions for {rows_updated} rows")
        
        conn.commit()
        print("Migration completed successfully!")
        
        # Show final schema
        c.execute("PRAGMA table_info(criteria)")
        columns_after = [row[1] for row in c.fetchall()]
        print(f"Final criteria table columns: {columns_after}")
        
    except Exception as e:
        print(f"Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database()
