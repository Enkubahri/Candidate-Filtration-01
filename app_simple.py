from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, TextAreaField, SelectField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Email, NumberRange
import os
import sqlite3
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database initialization
def init_db():
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    
    # Candidates table
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
    
    # Admin criteria table
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

# Forms
class CandidateForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[DataRequired()])
    experience_years = IntegerField('Years of Experience', validators=[DataRequired(), NumberRange(min=0, max=50)])
    education = SelectField('Education Level', 
                          choices=[('high_school', 'High School'),
                                 ('associate', 'Associate Degree'),
                                 ('bachelor', 'Bachelor\'s Degree'),
                                 ('master', 'Master\'s Degree'),
                                 ('phd', 'PhD'),
                                 ('other', 'Other')],
                          validators=[DataRequired()])
    skills = TextAreaField('Skills (comma-separated)', validators=[DataRequired()])
    resume = FileField('Resume', validators=[
        FileRequired(),
        FileAllowed(['pdf', 'doc', 'docx'], 'Only PDF and Word documents are allowed!')
    ])
    submit = SubmitField('Submit Application')

class AdminCriteriaForm(FlaskForm):
    min_experience = IntegerField('Minimum Years of Experience', validators=[DataRequired(), NumberRange(min=0)])
    required_skills = TextAreaField('Required Skills (comma-separated)', validators=[DataRequired()])
    preferred_education = SelectField('Minimum Education Level',
                                    choices=[('high_school', 'High School'),
                                           ('associate', 'Associate Degree'),
                                           ('bachelor', 'Bachelor\'s Degree'),
                                           ('master', 'Master\'s Degree'),
                                           ('phd', 'PhD')],
                                    validators=[DataRequired()])
    notification_email = StringField('Notification Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Save Criteria')

def check_candidate_criteria(candidate_data, criteria):
    """Check if candidate meets the criteria"""
    score = 0
    max_score = 3
    feedback = []
    
    # Check experience
    if candidate_data['experience_years'] >= criteria['min_experience']:
        score += 1
        feedback.append(f"✓ Experience requirement met ({candidate_data['experience_years']} years)")
    else:
        feedback.append(f"✗ Insufficient experience ({candidate_data['experience_years']} vs {criteria['min_experience']} required)")
    
    # Check skills
    candidate_skills = [skill.strip().lower() for skill in candidate_data['skills'].split(',')]
    required_skills = [skill.strip().lower() for skill in criteria['required_skills'].split(',')]
    
    matching_skills = set(candidate_skills) & set(required_skills)
    if len(matching_skills) >= len(required_skills) * 0.7:  # 70% skill match
        score += 1
        feedback.append(f"✓ Skills requirement met (matched: {', '.join(matching_skills)})")
    else:
        feedback.append(f"✗ Insufficient skill match (has: {', '.join(candidate_skills)})")
    
    # Check education
    education_levels = {'high_school': 1, 'associate': 2, 'bachelor': 3, 'master': 4, 'phd': 5}
    if education_levels.get(candidate_data['education'], 0) >= education_levels.get(criteria['preferred_education'], 0):
        score += 1
        feedback.append(f"✓ Education requirement met ({candidate_data['education']})")
    else:
        feedback.append(f"✗ Education requirement not met ({candidate_data['education']} vs {criteria['preferred_education']} required)")
    
    return score >= 2, score, max_score, feedback  # Pass if 2/3 criteria met

def send_notification_email(candidate_data, criteria_email, passed, score, max_score, feedback):
    """Log email notification (simplified version)"""
    print(f"\n📧 EMAIL NOTIFICATION")
    print(f"To: {criteria_email}")
    print(f"Subject: Candidate Application: {candidate_data['name']} - {'PASSED' if passed else 'FAILED'}")
    print(f"Status: {'PASSED' if passed else 'FAILED'} ({score}/{max_score})")
    print(f"Candidate: {candidate_data['name']} ({candidate_data['email']})")
    print(f"Experience: {candidate_data['experience_years']} years")
    print(f"Skills: {candidate_data['skills']}")
    print(f"Education: {candidate_data['education']}")
    print(f"Resume: {candidate_data.get('resume_filename', 'Not provided')}")
    print("Feedback:")
    for fb in feedback:
        print(f"  {fb}")
    print("-" * 50)
    return True

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/candidate', methods=['GET', 'POST'])
def candidate_form():
    form = CandidateForm()
    
    if form.validate_on_submit():
        # Save uploaded file
        file = form.resume.data
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Save candidate data to database
        conn = sqlite3.connect('candidates.db')
        c = conn.cursor()
        
        c.execute('''INSERT INTO candidates 
                     (name, email, phone, experience_years, education, skills, resume_filename)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (form.name.data, form.email.data, form.phone.data,
                   form.experience_years.data, form.education.data,
                   form.skills.data, filename))
        
        candidate_id = c.lastrowid
        conn.commit()
        
        # Get current criteria
        c.execute('SELECT * FROM criteria WHERE is_active = 1 ORDER BY created_date DESC LIMIT 1')
        criteria_row = c.fetchone()
        conn.close()
        
        if criteria_row:
            criteria = {
                'min_experience': criteria_row[1],
                'required_skills': criteria_row[2],
                'preferred_education': criteria_row[3],
                'notification_email': criteria_row[4]
            }
            
            candidate_data = {
                'name': form.name.data,
                'email': form.email.data,
                'phone': form.phone.data,
                'experience_years': form.experience_years.data,
                'education': form.education.data,
                'skills': form.skills.data,
                'resume_filename': filename
            }
            
            # Check criteria and send notification
            passed, score, max_score, feedback = check_candidate_criteria(candidate_data, criteria)
            send_notification_email(candidate_data, criteria['notification_email'], passed, score, max_score, feedback)
            
            # Update candidate status
            conn = sqlite3.connect('candidates.db')
            c = conn.cursor()
            c.execute('UPDATE candidates SET status = ? WHERE id = ?', 
                     ('passed' if passed else 'failed', candidate_id))
            conn.commit()
            conn.close()
            
            if passed:
                flash('Application submitted successfully! You meet our criteria and will be contacted soon.', 'success')
            else:
                flash('Application submitted successfully! We will review it and contact you if suitable.', 'info')
        else:
            flash('Application submitted successfully! We will review it shortly.', 'success')
        
        return redirect(url_for('candidate_form'))
    
    return render_template('candidate_form.html', form=form)

@app.route('/admin', methods=['GET', 'POST'])
def admin_criteria():
    form = AdminCriteriaForm()
    
    if form.validate_on_submit():
        # Deactivate old criteria
        conn = sqlite3.connect('candidates.db')
        c = conn.cursor()
        c.execute('UPDATE criteria SET is_active = 0')
        
        # Insert new criteria
        c.execute('''INSERT INTO criteria 
                     (min_experience, required_skills, preferred_education, notification_email)
                     VALUES (?, ?, ?, ?)''',
                  (form.min_experience.data, form.required_skills.data,
                   form.preferred_education.data, form.notification_email.data))
        
        conn.commit()
        conn.close()
        
        flash('Criteria updated successfully!', 'success')
        return redirect(url_for('admin_criteria'))
    
    # Load current criteria
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    c.execute('SELECT * FROM criteria WHERE is_active = 1 ORDER BY created_date DESC LIMIT 1')
    current_criteria = c.fetchone()
    conn.close()
    
    if current_criteria:
        form.min_experience.data = current_criteria[1]
        form.required_skills.data = current_criteria[2]
        form.preferred_education.data = current_criteria[3]
        form.notification_email.data = current_criteria[4]
    
    return render_template('admin_form.html', form=form, current_criteria=current_criteria)

@app.route('/admin/candidates')
def view_candidates():
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    c.execute('SELECT * FROM candidates ORDER BY submission_date DESC')
    candidates = c.fetchall()
    conn.close()
    
    return render_template('candidates_list.html', candidates=candidates)

if __name__ == '__main__':
    init_db()
    print("🎯 Candidate Filtration System Starting...")
    print("📝 Database initialized")
    print("🌐 Open your browser and go to: http://localhost:5000")
    print("🛑 Press Ctrl+C to stop")
    app.run(debug=True)
