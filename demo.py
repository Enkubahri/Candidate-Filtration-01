#!/usr/bin/env python3
"""
Demo script for Candidate Filtration System
This script demonstrates the filtration logic without running the full web application.
"""

import sqlite3
import os
from datetime import datetime

def init_demo_db():
    """Initialize database with demo data"""
    conn = sqlite3.connect('demo_candidates.db')
    c = conn.cursor()
    
    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS candidates
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  email TEXT NOT NULL,
                  phone TEXT,
                  experience_years INTEGER,
                  education TEXT,
                  skills TEXT,
                  resume_filename TEXT,
                  submission_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  status TEXT DEFAULT 'pending')''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS criteria
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  min_experience INTEGER,
                  required_skills TEXT,
                  preferred_education TEXT,
                  notification_email TEXT,
                  created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  is_active BOOLEAN DEFAULT 1)''')
    
    conn.commit()
    conn.close()

def add_demo_criteria():
    """Add demo filtration criteria"""
    conn = sqlite3.connect('demo_candidates.db')
    c = conn.cursor()
    
    # Add sample criteria
    c.execute('''INSERT INTO criteria 
                 (min_experience, required_skills, preferred_education, notification_email)
                 VALUES (?, ?, ?, ?)''',
              (3, 'Python, SQL, Communication, Problem Solving', 'bachelor', 'hr@company.com'))
    
    conn.commit()
    conn.close()
    print("✓ Demo criteria added: Min 3 years experience, Bachelor's degree, Python/SQL/Communication/Problem Solving skills")

def add_demo_candidates():
    """Add demo candidates"""
    candidates = [
        {
            'name': 'Alice Johnson',
            'email': 'alice@example.com',
            'phone': '(555) 123-4567',
            'experience_years': 5,
            'education': 'master',
            'skills': 'Python, SQL, JavaScript, Machine Learning, Communication',
            'resume_filename': 'alice_resume.pdf'
        },
        {
            'name': 'Bob Smith',
            'email': 'bob@example.com',
            'phone': '(555) 234-5678',
            'experience_years': 2,
            'education': 'bachelor',
            'skills': 'Java, MySQL, Problem Solving',
            'resume_filename': 'bob_resume.pdf'
        },
        {
            'name': 'Carol Davis',
            'email': 'carol@example.com',
            'phone': '(555) 345-6789',
            'experience_years': 7,
            'education': 'associate',
            'skills': 'Python, PostgreSQL, Communication, Leadership',
            'resume_filename': 'carol_resume.pdf'
        },
        {
            'name': 'David Wilson',
            'email': 'david@example.com',
            'phone': '(555) 456-7890',
            'experience_years': 1,
            'education': 'high_school',
            'skills': 'HTML, CSS, Basic Programming',
            'resume_filename': 'david_resume.pdf'
        }
    ]
    
    conn = sqlite3.connect('demo_candidates.db')
    c = conn.cursor()
    
    for candidate in candidates:
        c.execute('''INSERT INTO candidates 
                     (name, email, phone, experience_years, education, skills, resume_filename)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (candidate['name'], candidate['email'], candidate['phone'],
                   candidate['experience_years'], candidate['education'],
                   candidate['skills'], candidate['resume_filename']))
    
    conn.commit()
    conn.close()
    print(f"✓ Added {len(candidates)} demo candidates")

def check_candidate_criteria(candidate_data, criteria):
    """Check if candidate meets the criteria"""
    score = 0
    max_score = 3
    feedback = []
    
    print(f"\n--- Evaluating: {candidate_data['name']} ---")
    
    # Check experience
    if candidate_data['experience_years'] >= criteria['min_experience']:
        score += 1
        feedback.append(f"✓ Experience: {candidate_data['experience_years']} years (required: {criteria['min_experience']})")
    else:
        feedback.append(f"✗ Experience: {candidate_data['experience_years']} years (required: {criteria['min_experience']})")
    
    # Check skills
    candidate_skills = [skill.strip().lower() for skill in candidate_data['skills'].split(',')]
    required_skills = [skill.strip().lower() for skill in criteria['required_skills'].split(',')]
    
    matching_skills = set(candidate_skills) & set(required_skills)
    skill_match_ratio = len(matching_skills) / len(required_skills)
    
    if skill_match_ratio >= 0.7:  # 70% skill match
        score += 1
        feedback.append(f"✓ Skills: {skill_match_ratio:.0%} match ({', '.join(matching_skills)})")
    else:
        feedback.append(f"✗ Skills: {skill_match_ratio:.0%} match (need 70% minimum)")
    
    # Check education
    education_levels = {'high_school': 1, 'associate': 2, 'bachelor': 3, 'master': 4, 'phd': 5}
    candidate_edu_level = education_levels.get(candidate_data['education'], 0)
    required_edu_level = education_levels.get(criteria['preferred_education'], 0)
    
    if candidate_edu_level >= required_edu_level:
        score += 1
        feedback.append(f"✓ Education: {candidate_data['education']} (required: {criteria['preferred_education']})")
    else:
        feedback.append(f"✗ Education: {candidate_data['education']} (required: {criteria['preferred_education']})")
    
    # Print feedback
    for fb in feedback:
        print(f"  {fb}")
    
    passed = score >= 2
    print(f"  Result: {'PASSED' if passed else 'FAILED'} ({score}/{max_score})")
    
    return passed, score, max_score, feedback

def run_filtration_demo():
    """Run the complete filtration demo"""
    print("🎯 Candidate Filtration System Demo")
    print("=" * 50)
    
    # Initialize database
    init_demo_db()
    
    # Add demo data
    add_demo_criteria()
    add_demo_candidates()
    
    # Get criteria and candidates
    conn = sqlite3.connect('demo_candidates.db')
    c = conn.cursor()
    
    # Get active criteria
    c.execute('SELECT * FROM criteria WHERE is_active = 1 ORDER BY created_date DESC LIMIT 1')
    criteria_row = c.fetchone()
    
    if not criteria_row:
        print("No criteria found!")
        return
    
    criteria = {
        'min_experience': criteria_row[1],
        'required_skills': criteria_row[2],
        'preferred_education': criteria_row[3],
        'notification_email': criteria_row[4]
    }
    
    print(f"\nFiltration Criteria:")
    print(f"  Min Experience: {criteria['min_experience']} years")
    print(f"  Required Skills: {criteria['required_skills']}")
    print(f"  Min Education: {criteria['preferred_education']}")
    print(f"  Notification Email: {criteria['notification_email']}")
    
    # Get all candidates
    c.execute('SELECT * FROM candidates')
    candidates = c.fetchall()
    
    passed_count = 0
    failed_count = 0
    
    print(f"\nEvaluating {len(candidates)} candidates:")
    
    for candidate_row in candidates:
        candidate_data = {
            'name': candidate_row[1],
            'email': candidate_row[2],
            'phone': candidate_row[3],
            'experience_years': candidate_row[4],
            'education': candidate_row[5],
            'skills': candidate_row[6],
            'resume_filename': candidate_row[7]
        }
        
        passed, score, max_score, feedback = check_candidate_criteria(candidate_data, criteria)
        
        # Update status in database
        status = 'passed' if passed else 'failed'
        c.execute('UPDATE candidates SET status = ? WHERE id = ?', (status, candidate_row[0]))
        
        if passed:
            passed_count += 1
            print(f"  📧 Email notification would be sent for {candidate_data['name']}")
        else:
            failed_count += 1
    
    conn.commit()
    conn.close()
    
    print(f"\n📊 Summary:")
    print(f"  Passed: {passed_count}")
    print(f"  Failed: {failed_count}")
    print(f"  Total: {len(candidates)}")
    
    print(f"\n💾 Demo data saved to: demo_candidates.db")
    print(f"📁 Project files created in: {os.getcwd()}")

if __name__ == "__main__":
    run_filtration_demo()
