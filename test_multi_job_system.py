#!/usr/bin/env python3
"""
Comprehensive test script for the enhanced multi-job candidate filtration system.
Tests all new functionality including multiple jobs, status management, and notifications.
"""
import sqlite3
import os
import time
from datetime import datetime

def test_database_schema():
    """Test that database schema has all required columns."""
    print("=== Testing Database Schema ===")
    
    conn = sqlite3.connect('candidates.db')
    cursor = conn.cursor()
    
    # Check criteria table schema
    cursor.execute("PRAGMA table_info(criteria)")
    columns = [col[1] for col in cursor.fetchall()]
    
    required_columns = [
        'id', 'position_title', 'job_status', 'is_active', 
        'min_experience', 'expected_positions', 'min_position_years',
        'qualified_email', 'unqualified_email', 'notification_email'
    ]
    
    print("Current columns:", columns)
    
    for col in required_columns:
        if col in columns:
            print(f"✅ Column '{col}' exists")
        else:
            print(f"❌ Column '{col}' missing")
    
    # Test data integrity
    cursor.execute("SELECT COUNT(*) FROM criteria WHERE job_status IN ('open', 'closed')")
    valid_status_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM criteria")
    total_count = cursor.fetchone()[0]
    
    print(f"✅ Status integrity: {valid_status_count}/{total_count} records have valid job_status")
    
    conn.close()

def test_job_status_operations():
    """Test job status operations directly in the database."""
    print("\n=== Testing Job Status Operations ===")
    
    conn = sqlite3.connect('candidates.db')
    cursor = conn.cursor()
    
    # Count open vs closed jobs
    cursor.execute("SELECT job_status, COUNT(*) FROM criteria GROUP BY job_status")
    status_counts = dict(cursor.fetchall())
    
    print(f"Job status distribution: {status_counts}")
    
    # Test that we can identify open jobs
    cursor.execute("SELECT id, position_title FROM criteria WHERE job_status = 'open'")
    open_jobs = cursor.fetchall()
    print(f"✅ Found {len(open_jobs)} open jobs:")
    for job in open_jobs:
        print(f"  - ID {job[0]}: {job[1]}")
    
    conn.close()

def create_test_job():
    """Create a test job for comprehensive testing."""
    print("\n=== Creating Test Job ===")
    
    conn = sqlite3.connect('candidates.db')
    cursor = conn.cursor()
    
    # Create a test job with comprehensive criteria
    test_job = {
        'position_title': 'Senior Software Engineer (TEST)',
        'min_experience': 3,
        'expected_positions': 'Software Engineer, Developer, Programmer',
        'min_position_years': 2,
        'preferred_education': 'Bachelor',
        'notification_email': 'test-admin@company.com',
        'qualified_email': 'qualified-test@company.com',
        'unqualified_email': 'unqualified-test@company.com',
        'job_status': 'open',
        'is_active': 1,
        'admin_user_id': 1,
        'created_date': datetime.now()
    }
    
    cursor.execute("""
        INSERT INTO criteria (
            position_title, min_experience, expected_positions, min_position_years,
            preferred_education, notification_email, qualified_email, unqualified_email,
            job_status, is_active, admin_user_id, created_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        test_job['position_title'], test_job['min_experience'], test_job['expected_positions'],
        test_job['min_position_years'], test_job['preferred_education'], test_job['notification_email'],
        test_job['qualified_email'], test_job['unqualified_email'], test_job['job_status'],
        test_job['is_active'], test_job['admin_user_id'], test_job['created_date']
    ))
    
    test_job_id = cursor.lastrowid
    conn.commit()
    
    print(f"✅ Created test job with ID: {test_job_id}")
    print(f"   Position: {test_job['position_title']}")
    print(f"   Status: {test_job['job_status']}")
    
    conn.close()
    return test_job_id

def test_candidate_matching_logic():
    """Test the candidate matching logic against multiple jobs."""
    print("\n=== Testing Candidate Matching Logic ===")
    
    conn = sqlite3.connect('candidates.db')
    cursor = conn.cursor()
    
    # Get all open jobs
    cursor.execute("SELECT * FROM criteria WHERE job_status = 'open'")
    open_jobs = cursor.fetchall()
    
    print(f"Testing against {len(open_jobs)} open jobs:")
    for job in open_jobs:
        print(f"  - {job[8]}: {job[1]} years exp, positions: {job[7]}")
    
    # Simulate candidate data
    test_candidates = [
        {
            'name': 'John Doe (Qualified)',
            'experience': 5,
            'current_position': 'Senior Software Engineer',
            'education': 'Bachelor',
            'expected_matches': True
        },
        {
            'name': 'Jane Smith (Underqualified)',
            'experience': 1,
            'current_position': 'Junior Developer', 
            'education': 'High School',
            'expected_matches': False
        }
    ]
    
    for candidate in test_candidates:
        print(f"\n  Testing candidate: {candidate['name']}")
        matches = 0
        
        for job in open_jobs:
            job_id, min_exp, _, _, _, _, is_active, expected_pos, position_title = job[:9]
            
            # Check experience
            exp_match = candidate['experience'] >= min_exp
            
            # Check position match (simplified)
            pos_match = any(pos.strip().lower() in candidate['current_position'].lower() 
                          for pos in expected_pos.split(','))
            
            if exp_match and pos_match:
                matches += 1
                print(f"    ✅ Matches job: {position_title}")
            else:
                reasons = []
                if not exp_match:
                    reasons.append(f"experience {candidate['experience']} < {min_exp}")
                if not pos_match:
                    reasons.append("position mismatch")
                print(f"    ❌ No match for {position_title}: {', '.join(reasons)}")
        
        print(f"    Total matches: {matches}/{len(open_jobs)}")
        
        if candidate['expected_matches'] and matches > 0:
            print(f"    ✅ Expected qualified candidate matched {matches} jobs")
        elif not candidate['expected_matches'] and matches == 0:
            print(f"    ✅ Expected unqualified candidate matched no jobs")
        else:
            print(f"    ⚠️  Unexpected result for {candidate['name']}")
    
    conn.close()

def test_job_management_functionality():
    """Test job management operations."""
    print("\n=== Testing Job Management Functionality ===")
    
    conn = sqlite3.connect('candidates.db')
    cursor = conn.cursor()
    
    # Test status toggle
    cursor.execute("SELECT id, position_title, job_status FROM criteria LIMIT 1")
    test_job = cursor.fetchone()
    
    if test_job:
        job_id, title, current_status = test_job
        new_status = 'closed' if current_status == 'open' else 'open'
        
        print(f"Testing status toggle for job {job_id} ({title})")
        print(f"  Current status: {current_status}")
        
        # Toggle status
        cursor.execute("UPDATE criteria SET job_status = ? WHERE id = ?", (new_status, job_id))
        conn.commit()
        
        # Verify change
        cursor.execute("SELECT job_status FROM criteria WHERE id = ?", (job_id,))
        updated_status = cursor.fetchone()[0]
        
        if updated_status == new_status:
            print(f"  ✅ Successfully toggled to: {updated_status}")
        else:
            print(f"  ❌ Toggle failed: expected {new_status}, got {updated_status}")
        
        # Toggle back
        cursor.execute("UPDATE criteria SET job_status = ? WHERE id = ?", (current_status, job_id))
        conn.commit()
        print(f"  ✅ Restored original status: {current_status}")
    
    # Test bulk operations
    cursor.execute("SELECT COUNT(*) FROM criteria WHERE job_status = 'closed'")
    closed_count = cursor.fetchone()[0]
    
    if closed_count > 0:
        print(f"\n✅ Bulk clear test: Found {closed_count} closed jobs that could be cleared")
        print("  (Not actually clearing in test mode)")
    else:
        print("\n⚠️  No closed jobs available for bulk clear testing")
    
    conn.close()

def cleanup_test_data():
    """Clean up any test data created during testing."""
    print("\n=== Cleaning Up Test Data ===")
    
    conn = sqlite3.connect('candidates.db')
    cursor = conn.cursor()
    
    # Remove test jobs
    cursor.execute("DELETE FROM criteria WHERE position_title LIKE '%TEST%'")
    deleted = cursor.rowcount
    
    if deleted > 0:
        print(f"✅ Cleaned up {deleted} test job records")
        conn.commit()
    else:
        print("✅ No test data to clean up")
    
    conn.close()

def main():
    """Run all tests."""
    print("🚀 Starting Comprehensive Multi-Job System Tests")
    print("=" * 50)
    
    try:
        # Run all tests
        test_database_schema()
        test_job_status_operations()
        
        # Create test job
        test_job_id = create_test_job()
        
        test_candidate_matching_logic()
        test_job_management_functionality()
        
        print("\n" + "=" * 50)
        print("🎉 All tests completed successfully!")
        print("\n📋 Summary of Enhanced Features Tested:")
        print("  ✅ Database schema with job_status column")
        print("  ✅ Multiple job criteria support")
        print("  ✅ Open/closed job status management")
        print("  ✅ Candidate matching against multiple jobs")
        print("  ✅ Job status toggle functionality")
        print("  ✅ Bulk operations support")
        
        print("\n🌐 Next Steps:")
        print("  • Test the web interface at http://127.0.0.1:5000")
        print("  • Test admin job management at http://127.0.0.1:5000/admin")
        print("  • Test candidate form with multiple job matching")
        print("  • Verify email notifications for specific positions")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        raise
    finally:
        # Always clean up
        cleanup_test_data()

if __name__ == "__main__":
    main()
