import sqlite3
from datetime import datetime

def calculate_experience_years(start_date_str, end_date_str):
    """Calculate years of experience between two dates"""
    try:
        if not start_date_str or not end_date_str:
            return 0.0
        
        # Parse dates (format: YYYY-MM-DD)
        start_date = datetime.strptime(str(start_date_str), '%Y-%m-%d').date()
        end_date = datetime.strptime(str(end_date_str), '%Y-%m-%d').date()
        
        # Calculate difference in days and convert to years
        delta = end_date - start_date
        years = delta.days / 365.25  # Account for leap years
        
        return round(years, 2)
    except (ValueError, TypeError) as e:
        print(f"Error calculating experience years: {e}")
        return 0.0

def detailed_candidate_breakdown():
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    
    # Get the latest candidate
    c.execute('SELECT * FROM candidates ORDER BY id DESC LIMIT 1')
    candidate_row = c.fetchone()
    
    # Get current criteria
    c.execute("SELECT * FROM criteria WHERE job_status='open'")
    criteria_row = c.fetchone()
    
    if not candidate_row or not criteria_row:
        print("No candidate or criteria found")
        return
    
    # Build candidate data
    candidate_data = {
        'name': candidate_row[1],
        'email': candidate_row[2],
        'education': candidate_row[5],
        'education_certification': candidate_row[25] if len(candidate_row) > 25 else '',
        'experience_1_position_title': candidate_row[21],
        'experience_2_position_title': candidate_row[22],
        'experience_3_position_title': candidate_row[23],
        'experience_1_start_date': candidate_row[14],
        'experience_1_end_date': candidate_row[15],
        'experience_2_start_date': candidate_row[16],
        'experience_2_end_date': candidate_row[17],
        'experience_3_start_date': candidate_row[18],
        'experience_3_end_date': candidate_row[19],
    }
    
    # Build criteria
    criteria = {
        'min_experience': criteria_row[1],
        'min_position_years': criteria_row[9],
        'expected_positions': criteria_row[7],
        'preferred_education': criteria_row[3],
        'required_education_certification': criteria_row[14] if len(criteria_row) > 14 else ''
    }
    
    print("🏆 CANDIDATE EVALUATION BREAKDOWN")
    print("=" * 50)
    print(f"📋 Candidate: {candidate_data['name']}")
    print(f"📧 Email: {candidate_data['email']}")
    print(f"📊 Final Status: {candidate_row[9].upper()}")
    print("\n" + "=" * 50)
    
    print("📚 ADMIN CRITERIA:")
    print(f"   • Min Total Experience: {criteria['min_experience']} years")
    print(f"   • Min Similar Position Experience: {criteria['min_position_years']} years")
    print(f"   • Expected Positions: {criteria['expected_positions']}")
    print(f"   • Required Education Level: {criteria['preferred_education'].replace('_', ' ').title()}")
    print(f"   • Required Education Certification: {criteria['required_education_certification']}")
    
    print("\n" + "=" * 50)
    print("👤 CANDIDATE PROFILE:")
    print(f"   • Education Level: {candidate_data['education'].replace('_', ' ').title()}")
    print(f"   • Education Certification: {candidate_data['education_certification']}")
    print(f"   • Position 1: {candidate_data['experience_1_position_title']} ({candidate_data['experience_1_start_date']} to {candidate_data['experience_1_end_date']})")
    print(f"   • Position 2: {candidate_data['experience_2_position_title']} ({candidate_data['experience_2_start_date']} to {candidate_data['experience_2_end_date']})")
    print(f"   • Position 3: {candidate_data['experience_3_position_title']} ({candidate_data['experience_3_start_date']} to {candidate_data['experience_3_end_date']})")
    
    print("\n" + "=" * 50)
    print("🧮 DETAILED SCORING BREAKDOWN:")
    print("=" * 50)
    
    score = 0
    max_score = 5
    
    # Calculate experience years
    exp1_years = calculate_experience_years(candidate_data['experience_1_start_date'], candidate_data['experience_1_end_date'])
    exp2_years = calculate_experience_years(candidate_data['experience_2_start_date'], candidate_data['experience_2_end_date'])
    exp3_years = calculate_experience_years(candidate_data['experience_3_start_date'], candidate_data['experience_3_end_date'])
    
    # 1. POSITION TITLE MATCHING (1 point)
    print("\n1️⃣ POSITION TITLE MATCHING (Worth 1 point)")
    print("-" * 30)
    
    candidate_positions = [
        candidate_data['experience_1_position_title'].strip().lower(),
        candidate_data['experience_2_position_title'].strip().lower(), 
        candidate_data['experience_3_position_title'].strip().lower()
    ]
    candidate_positions = [pos for pos in candidate_positions if pos]
    expected_positions = [pos.strip().lower() for pos in criteria['expected_positions'].split(',') if pos.strip()]
    
    print(f"   Candidate Positions: {[pos.title() for pos in candidate_positions]}")
    print(f"   Expected Positions:  {[pos.title() for pos in expected_positions]}")
    
    matching_positions = []
    for candidate_pos in candidate_positions:
        for expected_pos in expected_positions:
            if expected_pos in candidate_pos or candidate_pos in expected_pos:
                matching_positions.append(candidate_pos)
                break
    
    if matching_positions:
        score += 1
        print(f"   ✅ MATCH FOUND: {[pos.title() for pos in matching_positions]}")
        print(f"   🎯 Points Earned: 1/1")
    else:
        print(f"   ❌ NO MATCHES FOUND")
        print(f"   🎯 Points Earned: 0/1")
    
    # 2. TOTAL WORK EXPERIENCE (1 point)
    print(f"\n2️⃣ TOTAL WORK EXPERIENCE (Worth 1 point)")
    print("-" * 30)
    
    total_experience_years = exp1_years + exp2_years + exp3_years
    min_required_experience = float(criteria['min_experience'])
    
    print(f"   Experience 1: {exp1_years:.2f} years")
    print(f"   Experience 2: {exp2_years:.2f} years") 
    print(f"   Experience 3: {exp3_years:.2f} years")
    print(f"   ────────────────────────")
    print(f"   Total Experience: {total_experience_years:.2f} years")
    print(f"   Required: {min_required_experience} years")
    
    if total_experience_years >= min_required_experience:
        score += 1
        print(f"   ✅ REQUIREMENT MET ({total_experience_years:.1f} >= {min_required_experience})")
        print(f"   🎯 Points Earned: 1/1")
    else:
        print(f"   ❌ INSUFFICIENT ({total_experience_years:.1f} < {min_required_experience})")
        print(f"   🎯 Points Earned: 0/1")
    
    # 3. SIMILAR POSITION EXPERIENCE (2 points)
    print(f"\n3️⃣ SIMILAR POSITION EXPERIENCE (Worth 2 points)")
    print("-" * 30)
    
    similar_position_years = 0.0
    position_breakdowns = []
    
    # Check each position
    pos1_title = candidate_data['experience_1_position_title'].strip().lower()
    pos1_match = False
    for expected_pos in expected_positions:
        if expected_pos in pos1_title or pos1_title in expected_pos:
            similar_position_years += exp1_years
            pos1_match = True
            break
    position_breakdowns.append((candidate_data['experience_1_position_title'], exp1_years, pos1_match))
    
    pos2_title = candidate_data['experience_2_position_title'].strip().lower()
    pos2_match = False
    for expected_pos in expected_positions:
        if expected_pos in pos2_title or pos2_title in expected_pos:
            similar_position_years += exp2_years
            pos2_match = True
            break
    position_breakdowns.append((candidate_data['experience_2_position_title'], exp2_years, pos2_match))
    
    pos3_title = candidate_data['experience_3_position_title'].strip().lower()
    pos3_match = False
    for expected_pos in expected_positions:
        if expected_pos in pos3_title or pos3_title in expected_pos:
            similar_position_years += exp3_years
            pos3_match = True
            break
    position_breakdowns.append((candidate_data['experience_3_position_title'], exp3_years, pos3_match))
    
    print(f"   Position Analysis:")
    for i, (pos_title, years, is_match) in enumerate(position_breakdowns, 1):
        match_status = "✅ MATCH" if is_match else "❌ NO MATCH"
        years_counted = f"({years:.2f} years counted)" if is_match else f"({years:.2f} years not counted)"
        print(f"     {i}. {pos_title} - {match_status} {years_counted}")
    
    min_required_position_years = float(criteria['min_position_years'])
    
    print(f"   ────────────────────────")
    print(f"   Total Similar Position Experience: {similar_position_years:.2f} years")
    print(f"   Required: {min_required_position_years} years")
    
    if similar_position_years >= min_required_position_years:
        score += 2
        print(f"   ✅ REQUIREMENT MET ({similar_position_years:.1f} >= {min_required_position_years})")
        print(f"   🎯 Points Earned: 2/2")
    else:
        print(f"   ❌ INSUFFICIENT ({similar_position_years:.1f} < {min_required_position_years})")
        print(f"   🎯 Points Earned: 0/2")
    
    # 4. EDUCATION LEVEL REQUIREMENT (1 point)
    print(f"\n4️⃣ EDUCATION LEVEL (Worth 1 point)")
    print("-" * 30)
    
    education_levels = {'high_school': 1, 'associate': 2, 'bachelor': 3, 'master': 4, 'phd': 5, 'other': 1}
    candidate_education_level = education_levels.get(candidate_data['education'], 1)
    required_education_level = education_levels.get(criteria['preferred_education'], 1)
    
    candidate_edu_name = candidate_data['education'].replace('_', ' ').title()
    required_edu_name = criteria['preferred_education'].replace('_', ' ').title()
    
    print(f"   Candidate Education: {candidate_edu_name} (Level {candidate_education_level})")
    print(f"   Required Education: {required_edu_name} (Level {required_education_level})")
    
    if candidate_education_level >= required_education_level:
        score += 1
        print(f"   ✅ REQUIREMENT MET ({candidate_edu_name} >= {required_edu_name})")
        print(f"   🎯 Points Earned: 1/1")
    else:
        print(f"   ❌ INSUFFICIENT ({candidate_edu_name} < {required_edu_name})")
        print(f"   🎯 Points Earned: 0/1")
    
    # 5. EDUCATION CERTIFICATION MATCHING (1 point)
    print(f"\n5️⃣ EDUCATION CERTIFICATION (Worth 1 point)")
    print("-" * 30)
    
    candidate_education_cert = candidate_data['education_certification'].strip().lower()
    required_education_cert = criteria['required_education_certification'].strip().lower()
    
    print(f"   Candidate Certification: '{candidate_data['education_certification']}'")
    print(f"   Required Certification: '{criteria['required_education_certification']}'")
    
    if required_education_cert and candidate_education_cert:
        # Check for partial matches (either direction)
        if (required_education_cert in candidate_education_cert or 
            candidate_education_cert in required_education_cert):
            score += 1
            print(f"   ✅ MATCH FOUND")
            print(f"   🎯 Points Earned: 1/1")
        else:
            print(f"   ❌ NO MATCH FOUND")
            print(f"   🎯 Points Earned: 0/1")
    elif required_education_cert:
        print(f"   ❌ CANDIDATE MISSING REQUIRED CERTIFICATION")
        print(f"   🎯 Points Earned: 0/1")
    else:
        score += 1
        print(f"   ✅ NO SPECIFIC CERTIFICATION REQUIRED")
        print(f"   🎯 Points Earned: 1/1")
    
    # FINAL SUMMARY
    print(f"\n" + "=" * 50)
    print("🏁 FINAL EVALUATION SUMMARY")
    print("=" * 50)
    print(f"📊 Total Score: {score}/{max_score} points")
    passed = score >= 3
    print(f"🎯 Pass Threshold: 3+ points required")
    print(f"✅ Result: {'QUALIFIED' if passed else 'NOT QUALIFIED'}")
    print(f"📝 Database Status: {candidate_row[9].upper()}")
    
    if not passed:
        points_needed = 3 - score
        print(f"📉 Points needed to pass: {points_needed} more point(s)")
        print("\n💡 Areas for improvement:")
        if score < 3:
            print("   • Consider candidates with more relevant position experience")
            print("   • Look for higher education levels if required")
            print("   • Check certification matches more carefully")
    
    conn.close()

if __name__ == "__main__":
    detailed_candidate_breakdown()
