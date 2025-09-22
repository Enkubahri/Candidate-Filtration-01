#!/usr/bin/env python3
"""
Candidate Database Cleanup Script
=================================

This script provides options to clear candidate data from the database.
Use with caution - deleted data cannot be recovered!

Author: Assistant
Date: 2025-09-17
"""

import sqlite3
import os
import shutil
from datetime import datetime

def get_candidate_stats():
    """Get current candidate statistics"""
    try:
        conn = sqlite3.connect('candidates.db')
        c = conn.cursor()
        
        # Total candidates
        c.execute('SELECT COUNT(*) FROM candidates')
        total_candidates = c.fetchone()[0]
        
        # By status
        c.execute('SELECT status, COUNT(*) FROM candidates GROUP BY status')
        status_counts = dict(c.fetchall())
        
        # Recent submissions (last 7 days)
        c.execute('''SELECT COUNT(*) FROM candidates 
                     WHERE submission_date >= datetime('now', '-7 days')''')
        recent_count = c.fetchone()[0]
        
        conn.close()
        return total_candidates, status_counts, recent_count
    except Exception as e:
        print(f"Error getting stats: {e}")
        return 0, {}, 0

def backup_database():
    """Create a backup of the current database"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f'candidates_backup_{timestamp}.db'
        
        if os.path.exists('candidates.db'):
            shutil.copy2('candidates.db', backup_name)
            print(f"✅ Database backed up as: {backup_name}")
            return backup_name
        else:
            print("❌ Database file not found!")
            return None
    except Exception as e:
        print(f"❌ Backup failed: {e}")
        return None

def clear_resume_files():
    """Remove all uploaded resume files"""
    try:
        uploads_dir = 'uploads'
        if os.path.exists(uploads_dir):
            files = os.listdir(uploads_dir)
            if files:
                for file in files:
                    file_path = os.path.join(uploads_dir, file)
                    try:
                        os.remove(file_path)
                        print(f"  🗑️  Deleted: {file}")
                    except Exception as e:
                        print(f"  ❌ Failed to delete {file}: {e}")
                print(f"✅ Cleared {len(files)} resume files from uploads/")
            else:
                print("📁 No resume files found in uploads/")
        else:
            print("📁 Uploads directory doesn't exist")
    except Exception as e:
        print(f"❌ Error clearing resume files: {e}")

def delete_all_candidates():
    """Delete all candidates from the database"""
    try:
        conn = sqlite3.connect('candidates.db')
        c = conn.cursor()
        
        # Get count before deletion
        c.execute('SELECT COUNT(*) FROM candidates')
        count_before = c.fetchone()[0]
        
        # Delete all candidates
        c.execute('DELETE FROM candidates')
        deleted_count = c.rowcount
        
        conn.commit()
        conn.close()
        
        print(f"✅ Successfully deleted {deleted_count} candidates from database")
        return deleted_count
    except Exception as e:
        print(f"❌ Error deleting candidates: {e}")
        return 0

def delete_candidates_by_status(status):
    """Delete candidates by specific status"""
    try:
        conn = sqlite3.connect('candidates.db')
        c = conn.cursor()
        
        # Delete by status
        c.execute('DELETE FROM candidates WHERE status = ?', (status,))
        deleted_count = c.rowcount
        
        conn.commit()
        conn.close()
        
        print(f"✅ Successfully deleted {deleted_count} candidates with status '{status}'")
        return deleted_count
    except Exception as e:
        print(f"❌ Error deleting candidates by status: {e}")
        return 0

def main():
    print("🧹 CANDIDATE DATABASE CLEANUP TOOL")
    print("=" * 50)
    
    # Check if database exists
    if not os.path.exists('candidates.db'):
        print("❌ Database file 'candidates.db' not found!")
        print("   Make sure you're running this script in the correct directory.")
        return
    
    # Show current statistics
    total, status_counts, recent = get_candidate_stats()
    
    print(f"📊 CURRENT DATABASE STATUS:")
    print(f"   Total Candidates: {total}")
    if status_counts:
        for status, count in status_counts.items():
            print(f"   - {status.capitalize()}: {count}")
    print(f"   Recent Submissions (7 days): {recent}")
    print()
    
    if total == 0:
        print("✅ No candidates found in database. Nothing to clean!")
        return
    
    # Show options
    print("🔧 CLEANUP OPTIONS:")
    print("   1. Delete ALL candidates (full cleanup)")
    print("   2. Delete only FAILED candidates")
    print("   3. Delete only PASSED candidates") 
    print("   4. Delete only PENDING candidates")
    print("   5. Show statistics only (no deletion)")
    print("   6. Exit without changes")
    print()
    
    # Get user choice
    while True:
        try:
            choice = input("Select option (1-6): ").strip()
            if choice in ['1', '2', '3', '4', '5', '6']:
                break
            print("❌ Invalid choice. Please enter 1-6.")
        except KeyboardInterrupt:
            print("\n\n👋 Cancelled by user. No changes made.")
            return
    
    # Handle choice
    if choice == '6':
        print("👋 Exiting without making any changes.")
        return
    elif choice == '5':
        print("📊 Current statistics shown above. No changes made.")
        return
    
    # For deletion options, create backup first
    print(f"\n🔄 Creating backup before proceeding...")
    backup_file = backup_database()
    if not backup_file:
        print("❌ Could not create backup. Aborting for safety!")
        return
    
    # Confirmation based on choice
    if choice == '1':
        print(f"\n⚠️  WARNING: You are about to DELETE ALL {total} CANDIDATES!")
        print("   This action CANNOT be undone!")
        confirm1 = input(f"   Type 'DELETE ALL {total}' to confirm: ").strip()
        if confirm1 != f'DELETE ALL {total}':
            print("❌ Confirmation failed. No changes made.")
            return
        
        confirm2 = input("   Are you absolutely sure? Type 'YES': ").strip().upper()
        if confirm2 != 'YES':
            print("❌ Final confirmation failed. No changes made.")
            return
        
        print("\n🗑️  Deleting all candidates...")
        deleted = delete_all_candidates()
        
        # Ask about resume files
        if deleted > 0:
            clear_resumes = input("\n🗂️  Also delete resume files from uploads/? (y/N): ").strip().lower()
            if clear_resumes in ['y', 'yes']:
                clear_resume_files()
    
    elif choice in ['2', '3', '4']:
        status_map = {'2': 'failed', '3': 'passed', '4': 'pending'}
        target_status = status_map[choice]
        target_count = status_counts.get(target_status, 0)
        
        if target_count == 0:
            print(f"✅ No candidates with status '{target_status}' found. Nothing to delete!")
            return
        
        print(f"\n⚠️  You are about to delete {target_count} candidates with status '{target_status}'")
        confirm = input(f"   Type 'DELETE {target_status.upper()}' to confirm: ").strip()
        if confirm != f'DELETE {target_status.upper()}':
            print("❌ Confirmation failed. No changes made.")
            return
        
        print(f"\n🗑️  Deleting {target_status} candidates...")
        delete_candidates_by_status(target_status)
    
    # Show final statistics
    print("\n📊 FINAL STATISTICS:")
    final_total, final_status, final_recent = get_candidate_stats()
    print(f"   Total Candidates: {final_total}")
    if final_status:
        for status, count in final_status.items():
            print(f"   - {status.capitalize()}: {count}")
    
    print(f"\n✅ Cleanup completed!")
    print(f"💾 Backup saved as: {backup_file}")
    print("   You can restore from backup if needed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Script interrupted by user. No changes made.")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("   No changes were made to the database.")
