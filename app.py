from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms import StringField, TextAreaField, SelectField, IntegerField, EmailField, SubmitField, PasswordField, DateField, RadioField
from wtforms.validators import DataRequired, Email, NumberRange, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
import smtplib
try:
    from email.mime.text import MimeText
    from email.mime.multipart import MimeMultipart
    from email.mime.base import MimeBase
    from email import encoders
except ImportError:
    # Fallback for older Python versions or import issues
    MimeText = None
    MimeMultipart = None
    MimeBase = None
    encoders = None
from werkzeug.utils import secure_filename
import PyPDF2
import docx
import json
from datetime import datetime, timedelta
import re
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
# Disable template caching in development
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# User Model
class User(UserMixin):
    def __init__(self, id, email, password_hash, role, created_date, is_active=True, name=None, department=None, email_confirmed=False):
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.role = role  # 'candidate' or 'admin'
        self.created_date = created_date
        self.name = name
        self.department = department
        self.email_confirmed = bool(email_confirmed)
        # Store active flag internally to avoid clashing with UserMixin property
        self._active = bool(is_active)

    @property
    def is_active(self):
        return self._active
    
    @staticmethod
    def get(user_id):
        conn = sqlite3.connect('candidates.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user_data = c.fetchone()
        conn.close()
        
        if user_data:
            return User(*user_data)
        return None
    
    @staticmethod
    def get_by_email(email):
        conn = sqlite3.connect('candidates.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user_data = c.fetchone()
        conn.close()
        
        if user_data:
            return User(*user_data)
        return None
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def save(self):
        conn = sqlite3.connect('candidates.db')
        c = conn.cursor()
        if self.id:
            # Update existing user
            c.execute('''UPDATE users SET email=?, password_hash=?, role=?, is_active=?, 
                         name=?, department=?, email_confirmed=?
                         WHERE id=?''', 
                      (self.email, self.password_hash, self.role, int(self._active), 
                       self.name, self.department, int(self.email_confirmed), self.id))
        else:
            # Create new user
            c.execute('''INSERT INTO users (email, password_hash, role, created_date, is_active, 
                         name, department, email_confirmed) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                      (self.email, self.password_hash, self.role, datetime.now(), int(self._active),
                       self.name, self.department, int(self.email_confirmed)))
            self.id = c.lastrowid
        conn.commit()
        conn.close()
        return self

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Database initialization
def init_db():
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    
    # Users table for authentication
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  role TEXT NOT NULL CHECK(role IN ('candidate', 'admin')),
                  created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  is_active BOOLEAN DEFAULT 1)''')
    
    # Candidates table (now linked to users)
    c.execute('''CREATE TABLE IF NOT EXISTS candidates
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  name TEXT NOT NULL,
                  email TEXT NOT NULL,
                  phone TEXT,
                  experience_years INTEGER,
                  position_experience_years INTEGER DEFAULT 0,
                  education TEXT,
                  skills TEXT,
                  resume_filename TEXT,
                  submission_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  status TEXT DEFAULT 'pending',
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Admin criteria table (now linked to admin users)
    c.execute('''CREATE TABLE IF NOT EXISTS criteria
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  admin_user_id INTEGER,
                  position_title TEXT NOT NULL,
                  min_experience INTEGER,
                  min_position_years INTEGER,
                  required_skills TEXT,
                  preferred_education TEXT,
                  qualified_email TEXT NOT NULL,
                  unqualified_email TEXT NOT NULL,
                 created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  is_active BOOLEAN DEFAULT 1,
                  job_id INTEGER UNIQUE,
                  FOREIGN KEY (admin_user_id) REFERENCES users (id))''')
    
    # Add position_experience_years column if it doesn't exist (database migration)
    try:
        c.execute('SELECT position_experience_years FROM candidates LIMIT 1')
    except sqlite3.OperationalError:
        # Column doesn't exist, add it
        c.execute('ALTER TABLE candidates ADD COLUMN position_experience_years INTEGER DEFAULT 0')
        print("Added position_experience_years column to candidates table")
    
    # Add experience fields and remove skills column (database migration)
    try:
        c.execute('SELECT experience_1 FROM candidates LIMIT 1')
    except sqlite3.OperationalError:
        # Experience columns don't exist, add them
        c.execute('ALTER TABLE candidates ADD COLUMN experience_1 TEXT DEFAULT ""')
        c.execute('ALTER TABLE candidates ADD COLUMN experience_2 TEXT DEFAULT ""')
        c.execute('ALTER TABLE candidates ADD COLUMN experience_3 TEXT DEFAULT ""')
        print("Added experience_1, experience_2, experience_3 columns to candidates table")
    
    # Add start/end date fields for experience positions (database migration)
    try:
        c.execute('SELECT experience_1_start_date FROM candidates LIMIT 1')
    except sqlite3.OperationalError:
        # Date columns don't exist, add them
        c.execute('ALTER TABLE candidates ADD COLUMN experience_1_start_date TEXT DEFAULT ""')
        c.execute('ALTER TABLE candidates ADD COLUMN experience_1_end_date TEXT DEFAULT ""')
        c.execute('ALTER TABLE candidates ADD COLUMN experience_2_start_date TEXT DEFAULT ""')
        c.execute('ALTER TABLE candidates ADD COLUMN experience_2_end_date TEXT DEFAULT ""')
        c.execute('ALTER TABLE candidates ADD COLUMN experience_3_start_date TEXT DEFAULT ""')
        c.execute('ALTER TABLE candidates ADD COLUMN experience_3_end_date TEXT DEFAULT ""')
        print("Added start/end date columns for experience positions")
    
    # Add expected_positions to criteria table and handle migration
    try:
        c.execute('SELECT expected_positions FROM criteria LIMIT 1')
    except sqlite3.OperationalError:
        # expected_positions column doesn't exist, add it
        c.execute('ALTER TABLE criteria ADD COLUMN expected_positions TEXT DEFAULT ""')
        print("Added expected_positions column to criteria table")
    
    # Add job_status column to support open/closed status
    try:
        c.execute('SELECT job_status FROM criteria LIMIT 1')
    except sqlite3.OperationalError:
        # job_status column doesn't exist, add it
        c.execute('ALTER TABLE criteria ADD COLUMN job_status TEXT DEFAULT "open"')
        print("Added job_status column to criteria table")
    
    # Add position title columns for experience positions
    try:
        c.execute('SELECT experience_1_position_title FROM candidates LIMIT 1')
    except sqlite3.OperationalError:
        # Position title columns don't exist, add them
        c.execute('ALTER TABLE candidates ADD COLUMN experience_1_position_title TEXT DEFAULT ""')
        c.execute('ALTER TABLE candidates ADD COLUMN experience_2_position_title TEXT DEFAULT ""')
        c.execute('ALTER TABLE candidates ADD COLUMN experience_3_position_title TEXT DEFAULT ""')
        print("Added position title columns for experience positions")
    
    # Add gender column to candidates table
    try:
        c.execute('SELECT gender FROM candidates LIMIT 1')
    except sqlite3.OperationalError:
        # Gender column doesn't exist, add it
        c.execute('ALTER TABLE candidates ADD COLUMN gender TEXT DEFAULT ""')
        print("Added gender column to candidates table")
    
    # Add education certification column to candidates table
    try:
        c.execute('SELECT education_certification FROM candidates LIMIT 1')
    except sqlite3.OperationalError:
        # Education certification column doesn't exist, add it
        c.execute('ALTER TABLE candidates ADD COLUMN education_certification TEXT DEFAULT ""')
        print("Added education_certification column to candidates table")
    
    # Add required education certification column to criteria table
    try:
        c.execute('SELECT required_education_certification FROM criteria LIMIT 1')
    except sqlite3.OperationalError:
        # Required education certification column doesn't exist, add it
        c.execute('ALTER TABLE criteria ADD COLUMN required_education_certification TEXT DEFAULT ""')
        print("Added required_education_certification column to criteria table")
    
    # Add new columns to users table for admin details
    try:
        c.execute('SELECT name FROM users LIMIT 1')
    except sqlite3.OperationalError:
        # name column doesn't exist, add it
        c.execute('ALTER TABLE users ADD COLUMN name TEXT')
        print("Added name column to users table")
    
    try:
        c.execute('SELECT department FROM users LIMIT 1')
    except sqlite3.OperationalError:
        # department column doesn't exist, add it
        c.execute('ALTER TABLE users ADD COLUMN department TEXT')
        print("Added department column to users table")
    
    try:
        c.execute('SELECT email_confirmed FROM users LIMIT 1')
    except sqlite3.OperationalError:
        # email_confirmed column doesn't exist, add it
        c.execute('ALTER TABLE users ADD COLUMN email_confirmed BOOLEAN DEFAULT 0')
        print("Added email_confirmed column to users table")
    
    # Create admin_tokens table for email verification
    c.execute('''CREATE TABLE IF NOT EXISTS admin_tokens
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  admin_user_id INTEGER NOT NULL,
                  token TEXT NOT NULL UNIQUE,
                  token_type TEXT NOT NULL,
                  created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  expires_date TIMESTAMP,
                  is_used BOOLEAN DEFAULT 0,
                  FOREIGN KEY (admin_user_id) REFERENCES users (id))''')
    
    # Add job_id column to criteria table for 4-digit numerical job IDs
    try:
        c.execute('SELECT job_id FROM criteria LIMIT 1')
    except sqlite3.OperationalError:
        # job_id column doesn't exist, add it
        c.execute('ALTER TABLE criteria ADD COLUMN job_id INTEGER')
        print("Added job_id column to criteria table")
        
        # Generate job_ids for existing records
        c.execute('SELECT id FROM criteria ORDER BY created_date')
        existing_jobs = c.fetchall()
        for job in existing_jobs:
            job_id = generate_unique_job_id(c)
            c.execute('UPDATE criteria SET job_id = ? WHERE id = ?', (job_id, job[0]))
    
    # Update the is_active logic - now we'll use job_status instead
    # Convert existing is_active=1 records to job_status='open' and is_active=0 to job_status='closed'
    c.execute('UPDATE criteria SET job_status = "open" WHERE is_active = 1')
    c.execute('UPDATE criteria SET job_status = "closed" WHERE is_active = 0')
    
    # Create default admin user if none exists
    c.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
    admin_count = c.fetchone()[0]
    
    if admin_count == 0:
        default_admin_email = 'admin@company.com'
        default_admin_password = 'admin123'  # Change this in production!
        password_hash = generate_password_hash(default_admin_password)
        
        c.execute('''INSERT INTO users (email, password_hash, role) 
                     VALUES (?, ?, ?)''',
                  (default_admin_email, password_hash, 'admin'))
        
        print(f"Default admin created: {default_admin_email} / {default_admin_password}")
    
    conn.commit()
    conn.close()

# Forms
class CandidateForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email = EmailField('Email Address', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[DataRequired()])
    position_of_interest = SelectField('Position of Interest', 
                                     choices=[], 
                                     validators=[DataRequired()],
                                     render_kw={'class': 'form-select'})
    education = SelectField('Education Level', 
                          choices=[('high_school', 'High School'),
                                 ('associate', 'Associate Degree'),
                                 ('bachelor', 'Bachelor\'s Degree'),
                                 ('master', 'Master\'s Degree'),
                                 ('phd', 'PhD'),
                                 ('other', 'Other')],
                          validators=[DataRequired()])
    
    education_certification = StringField('Education Certification/Details', 
                                        validators=[DataRequired()],
                                        render_kw={'placeholder': 'e.g., Computer Science, Marketing, MBA in Finance, etc.'})
    
    gender = RadioField('Gender', 
                       choices=[('male', 'Male'), ('female', 'Female')],
                       validators=[DataRequired()])
    
    # Experience Position 1 (Required)
    experience_1 = TextAreaField('Previous Experience 1 (Job Description)', validators=[DataRequired()])
    experience_1_position_title = StringField('Position Title for Experience 1', validators=[DataRequired()])
    experience_1_start_date = DateField('Start Date', validators=[DataRequired()])
    experience_1_end_date = DateField('End Date', validators=[DataRequired()])
    
    # Experience Position 2 (Required)
    experience_2 = TextAreaField('Previous Experience 2 (Job Description)', validators=[DataRequired()])
    experience_2_position_title = StringField('Position Title for Experience 2', validators=[DataRequired()])
    experience_2_start_date = DateField('Start Date', validators=[DataRequired()])
    experience_2_end_date = DateField('End Date', validators=[DataRequired()])
    
    # Experience Position 3 (Required)
    experience_3 = TextAreaField('Previous Experience 3 (Job Description)', validators=[DataRequired()])
    experience_3_position_title = StringField('Position Title for Experience 3', validators=[DataRequired()])
    experience_3_start_date = DateField('Start Date', validators=[DataRequired()])
    experience_3_end_date = DateField('End Date', validators=[DataRequired()])
    
    resume = FileField('Resume', validators=[
        FileRequired(),
        FileAllowed(['pdf', 'doc', 'docx'], 'Only PDF and Word documents are allowed!')
    ])
    submit = SubmitField('Submit Application')

class AdminCriteriaForm(FlaskForm):
    position_title = StringField('Position Title', validators=[DataRequired()])
    min_experience = IntegerField('Minimum Years of Experience', validators=[DataRequired(), NumberRange(min=0)])
    min_position_years = IntegerField('Minimum Years in Similar Position', validators=[DataRequired(), NumberRange(min=0)])
    expected_positions = TextAreaField('Expected Position Titles (comma-separated)', validators=[DataRequired()])
    preferred_education = SelectField('Minimum Education Level',
                                    choices=[('high_school', 'High School'),
                                           ('associate', 'Associate Degree'),
                                           ('bachelor', 'Bachelor\'s Degree'),
                                           ('master', 'Master\'s Degree'),
                                           ('phd', 'PhD')],
                                    validators=[DataRequired()])
    required_education_certification = StringField('Required Education Certification/Field of Study',
                                                 validators=[],
                                                 render_kw={'placeholder': 'e.g., Computer Science, Engineering, Business Administration, etc.'})
    qualified_email = EmailField('Email for Qualified Candidates', validators=[DataRequired(), Email()])
    unqualified_email = EmailField('Email for Unqualified Candidates', validators=[DataRequired(), Email()])
    job_status = SelectField('Job Status',
                           choices=[('open', 'Open'),
                                  ('closed', 'Closed')],
                           validators=[DataRequired()],
                           default='open')
    submit = SubmitField('Save Job Criteria')

class EditJobForm(FlaskForm):
    position_title = StringField('Position Title', validators=[DataRequired()])
    min_experience = IntegerField('Minimum Years of Experience', validators=[DataRequired(), NumberRange(min=0)])
    min_position_years = IntegerField('Minimum Years in Similar Position', validators=[DataRequired(), NumberRange(min=0)])
    expected_positions = TextAreaField('Expected Position Titles (comma-separated)', validators=[DataRequired()])
    preferred_education = SelectField('Minimum Education Level',
                                    choices=[('high_school', 'High School'),
                                           ('associate', 'Associate Degree'),
                                           ('bachelor', 'Bachelor\'s Degree'),
                                           ('master', 'Master\'s Degree'),
                                           ('phd', 'PhD')],
                                    validators=[DataRequired()])
    required_education_certification = StringField('Required Education Certification/Field of Study',
                                                 validators=[],
                                                 render_kw={'placeholder': 'e.g., Computer Science, Engineering, Business Administration, etc.'})
    qualified_email = EmailField('Email for Qualified Candidates', validators=[DataRequired(), Email()])
    unqualified_email = EmailField('Email for Unqualified Candidates', validators=[DataRequired(), Email()])
    job_status = SelectField('Job Status',
                           choices=[('open', 'Open'),
                                  ('closed', 'Closed')],
                           validators=[DataRequired()])
    submit = SubmitField('Update Job Criteria')

class BulkClearForm(FlaskForm):
    clear_type = SelectField('Clear Type',
                           choices=[('all', 'Clear All Job Criteria'),
                                  ('closed', 'Clear Only Closed Jobs'),
                                  ('specific', 'Clear Specific Jobs')],
                           validators=[DataRequired()],
                           default='closed')
    submit = SubmitField('Clear Selected Jobs')

# Authentication Forms
class LoginForm(FlaskForm):
    email = EmailField('Email Address', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class CreateAdminForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = EmailField('Email Address', validators=[DataRequired(), Email()])
    department = StringField('Department', validators=[DataRequired(), Length(min=2, max=100)])
    password = PasswordField('Password', validators=[
        DataRequired(), 
        Length(min=6, message='Password must be at least 6 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Create Admin User')
    
    def validate_email(self, field):
        user = User.get_by_email(field.data)
        if user:
            raise ValidationError('Email address is already registered.')

# Helper functions
def extract_text_from_pdf(file_path):
    """Extract text from PDF file"""
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text()
            return text
    except:
        return ""

def extract_text_from_docx(file_path):
    """Extract text from Word document"""
    try:
        doc = docx.Document(file_path)
        text = ""
        for paragraph in doc.paragraphs:
            text += paragraph.text + "\n"
        return text
    except:
        return ""

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

def check_candidate_criteria(candidate_data, criteria):
    """5-point evaluation system for candidate filtering"""
    score = 0
    max_score = 5
    feedback = []
    
    # 1. POSITION TITLE MATCHING (1 point)
    # Check if any candidate position titles match expected positions
    candidate_positions = []
    candidate_positions.append(candidate_data.get('experience_1_position_title', '').strip().lower())
    candidate_positions.append(candidate_data.get('experience_2_position_title', '').strip().lower())
    candidate_positions.append(candidate_data.get('experience_3_position_title', '').strip().lower())
    
    # Remove empty strings
    candidate_positions = [pos for pos in candidate_positions if pos]
    
    expected_positions = [pos.strip().lower() for pos in criteria.get('expected_positions', '').split(',') if pos.strip()]
    
    matching_positions = []
    for candidate_pos in candidate_positions:
        for expected_pos in expected_positions:
            # Check for partial matches (either direction)
            if expected_pos in candidate_pos or candidate_pos in expected_pos:
                matching_positions.append(candidate_pos)
                break
    
    if matching_positions:
        score += 1
        feedback.append(f"✓ [1pt] Position title match found: {', '.join(matching_positions)}")
    else:
        candidate_pos_str = ', '.join(candidate_positions) if candidate_positions else 'None provided'
        expected_pos_str = ', '.join(expected_positions) if expected_positions else 'None specified'
        feedback.append(f"✗ [0pt] No position title match (candidate: {candidate_pos_str}, expected: {expected_pos_str})")
    
    # 2. TOTAL WORK EXPERIENCE (1 point)
    # Calculate total years from all 3 experience date ranges
    total_experience_years = 0.0
    exp1_years = calculate_experience_years(
        candidate_data.get('experience_1_start_date'), 
        candidate_data.get('experience_1_end_date')
    )
    exp2_years = calculate_experience_years(
        candidate_data.get('experience_2_start_date'), 
        candidate_data.get('experience_2_end_date')
    )
    exp3_years = calculate_experience_years(
        candidate_data.get('experience_3_start_date'), 
        candidate_data.get('experience_3_end_date')
    )
    
    total_experience_years = exp1_years + exp2_years + exp3_years
    min_required_experience = 0.0
    try:
        min_required_experience = float(criteria.get('min_experience', 0))
    except (ValueError, TypeError):
        min_required_experience = 0.0
    
    if total_experience_years >= min_required_experience:
        score += 1
        feedback.append(f"✓ [1pt] Total experience requirement met ({total_experience_years:.1f} years >= {min_required_experience} required)")
    else:
        feedback.append(f"✗ [0pt] Insufficient total experience ({total_experience_years:.1f} years < {min_required_experience} required)")
    
    # 3. SIMILAR POSITION EXPERIENCE (2 points)
    # Calculate years in positions that match the criteria
    similar_position_years = 0.0
    
    # Check experience 1
    pos1_title = candidate_data.get('experience_1_position_title', '').strip().lower()
    if pos1_title:
        for expected_pos in expected_positions:
            if expected_pos in pos1_title or pos1_title in expected_pos:
                similar_position_years += exp1_years
                break
    
    # Check experience 2
    pos2_title = candidate_data.get('experience_2_position_title', '').strip().lower()
    if pos2_title:
        for expected_pos in expected_positions:
            if expected_pos in pos2_title or pos2_title in expected_pos:
                similar_position_years += exp2_years
                break
    
    # Check experience 3
    pos3_title = candidate_data.get('experience_3_position_title', '').strip().lower()
    if pos3_title:
        for expected_pos in expected_positions:
            if expected_pos in pos3_title or pos3_title in expected_pos:
                similar_position_years += exp3_years
                break
    
    min_required_position_years = 0.0
    try:
        min_required_position_years = float(criteria.get('min_position_years', 0) or 0)
    except (ValueError, TypeError):
        min_required_position_years = 0.0
    
    if similar_position_years >= min_required_position_years:
        score += 2
        feedback.append(f"✓ [2pts] Similar position experience requirement met ({similar_position_years:.1f} years >= {min_required_position_years} required)")
    else:
        feedback.append(f"✗ [0pts] Insufficient similar position experience ({similar_position_years:.1f} years < {min_required_position_years} required)")
    
    # 4. EDUCATION LEVEL REQUIREMENT (1 point)
    education_levels = {'high_school': 1, 'associate': 2, 'bachelor': 3, 'master': 4, 'phd': 5, 'other': 1}
    candidate_education_level = education_levels.get(candidate_data.get('education', 'high_school'), 1)
    required_education_level = education_levels.get(criteria.get('preferred_education', 'high_school'), 1)
    
    if candidate_education_level >= required_education_level:
        score += 1
        candidate_edu_name = candidate_data.get('education', 'high_school').replace('_', ' ').title()
        required_edu_name = criteria.get('preferred_education', 'high_school').replace('_', ' ').title()
        feedback.append(f"✓ [1pt] Education level requirement met ({candidate_edu_name} >= {required_edu_name} required)")
    else:
        candidate_edu_name = candidate_data.get('education', 'high_school').replace('_', ' ').title()
        required_edu_name = criteria.get('preferred_education', 'high_school').replace('_', ' ').title()
        feedback.append(f"✗ [0pt] Education level requirement not met ({candidate_edu_name} < {required_edu_name} required)")
    
    # 5. EDUCATION CERTIFICATION MATCHING (1 point)
    candidate_education_cert = candidate_data.get('education_certification', '').strip().lower()
    required_education_cert = criteria.get('required_education_certification', '').strip().lower()
    
    if required_education_cert and candidate_education_cert:
        # Check for partial matches (either direction)
        if (required_education_cert in candidate_education_cert or 
            candidate_education_cert in required_education_cert):
            score += 1
            feedback.append(f"✓ [1pt] Education certification match: '{candidate_education_cert}' matches '{required_education_cert}'")
        else:
            feedback.append(f"✗ [0pt] Education certification mismatch: '{candidate_education_cert}' vs '{required_education_cert}' required")
    elif required_education_cert:
        # Required but candidate didn't provide
        feedback.append(f"✗ [0pt] Missing required education certification: '{required_education_cert}'")
    else:
        # Not required, give the point
        score += 1
        feedback.append(f"✓ [1pt] No specific education certification required")
    
    # PASS/FAIL DETERMINATION
    # Candidate passes if they score 3 or more points out of 5
    passed = score >= 3
    
    # Add summary to feedback
    feedback.insert(0, f"EVALUATION SUMMARY: {score}/{max_score} points - {'QUALIFIED' if passed else 'NOT QUALIFIED'}")
    
    return passed, score, max_score, feedback

def generate_unique_job_id(cursor):
    """Generate a unique 4-digit job ID that doesn't exist in the database"""
    max_attempts = 100  # Safety limit to prevent infinite loops
    attempts = 0
    
    while attempts < max_attempts:
        # Generate a random 4-digit number (1000-9999)
        job_id = random.randint(1000, 9999)
        
        # Check if this ID already exists
        cursor.execute('SELECT job_id FROM criteria WHERE job_id = ?', (job_id,))
        existing = cursor.fetchone()
        
        if not existing:
            return job_id
            
        attempts += 1
    
    # If we couldn't find a unique ID after max_attempts, raise an error
    raise Exception("Unable to generate unique job ID after maximum attempts")

def send_notification_email(candidate_data, criteria_email, passed, score, max_score, feedback, position_title='Position'):
    """Send email notification about candidate"""
    try:
        # Check if email modules are available
        if not all([MimeText, MimeMultipart, MimeBase, encoders]):
            print("Email modules not available. Simulating email notification:")
            print(f"To: {criteria_email}")
            print(f"Subject: {position_title} Application: {candidate_data['name']} - {'QUALIFIED' if passed else 'NOT QUALIFIED'}")
            print(f"Status: {'QUALIFIED' if passed else 'NOT QUALIFIED'} (Score: {score}/{max_score})")
            print(f"Feedback: {'; '.join(feedback)}")
            return True
        
        # Email configuration (you'll need to configure SMTP settings)
        smtp_server = "smtp.gmail.com"  # Change this to your SMTP server
        smtp_port = 587
        sender_email = "your-email@example.com"  # Change this
        sender_password = "your-password"  # Use environment variable in production
        
        msg = MimeMultipart()
        msg['From'] = sender_email
        msg['To'] = criteria_email
        msg['Subject'] = f"{position_title} Application: {candidate_data['name']} - {'QUALIFIED' if passed else 'NOT QUALIFIED'}"
        
        body = f"""
        Candidate Application Review
        Position: {position_title}
        
        Candidate Information:
        - Name: {candidate_data['name']}
        - Email: {candidate_data['email']}
        - Phone: {candidate_data['phone']}
        - Education: {candidate_data['education']}
        - Position of Interest ID: {candidate_data.get('position_of_interest_id', 'N/A')}
        
        Work Experience:
        - Experience 1: {candidate_data.get('experience_1', 'N/A')}
        - Experience 2: {candidate_data.get('experience_2', 'N/A')}
        - Experience 3: {candidate_data.get('experience_3', 'N/A')}
        
        Evaluation Results:
        - Status: {'QUALIFIED' if passed else 'NOT QUALIFIED'}
        - Score: {score}/{max_score}
        
        Detailed Feedback:
        {chr(10).join(feedback)}
        
        Application submitted on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        msg.attach(MimeText(body, 'plain'))
        
        # Attach resume if available
        if 'resume_filename' in candidate_data and candidate_data['resume_filename']:
            resume_path = os.path.join(app.config['UPLOAD_FOLDER'], candidate_data['resume_filename'])
            if os.path.exists(resume_path):
                with open(resume_path, "rb") as attachment:
                    part = MimeBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                
                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {candidate_data["resume_filename"]}'
                )
                msg.attach(part)
        
        # Note: In a real application, use environment variables for email credentials
        # server = smtplib.SMTP(smtp_server, smtp_port)
        # server.starttls()
        # server.login(sender_email, sender_password)
        # server.send_message(msg)
        # server.quit()
        
        print(f"Email notification would be sent to: {criteria_email}")
        print(f"Subject: {msg['Subject']}")
        return True
        
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Helper function for role-based access control
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def candidate_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'candidate':
            flash('Access denied. Candidate account required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        if user and user.check_password(form.password.data) and user.role == 'admin':
            login_user(user)
            flash('Welcome back! Logged in as admin.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid email or password, or insufficient privileges.', 'error')
    
    return render_template('auth/login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

# Registration routes removed - admin users are now created by existing admins

# Dashboard Routes (candidate dashboard removed)

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # Get statistics for admin dashboard
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    
    # Total applications
    c.execute('SELECT COUNT(*) FROM candidates')
    total_applications = c.fetchone()[0]
    
    # Applications by status
    c.execute('SELECT status, COUNT(*) FROM candidates GROUP BY status')
    status_counts = dict(c.fetchall())
    
    # Recent applications with calculated experience
    c.execute('SELECT * FROM candidates ORDER BY submission_date DESC LIMIT 10')
    recent_applications_raw = c.fetchall()
    
    # Calculate total experience for each candidate and append to their data
    recent_applications = []
    for app in recent_applications_raw:
        # Calculate experience from date ranges
        exp1_years = calculate_experience_years(app[14], app[15])  # experience_1 dates
        exp2_years = calculate_experience_years(app[16], app[17])  # experience_2 dates  
        exp3_years = calculate_experience_years(app[18], app[19])  # experience_3 dates
        total_experience = exp1_years + exp2_years + exp3_years
        
        # Append calculated experience to the tuple
        app_with_experience = list(app) + [f"{total_experience:.1f}"]
        recent_applications.append(tuple(app_with_experience))
    
    # Get admin users count
    c.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
    admin_count = c.fetchone()[0]
    
    conn.close()
    
    return render_template('admin_dashboard.html', 
                         total_applications=total_applications,
                         status_counts=status_counts,
                         recent_applications=recent_applications,
                         admin_count=admin_count)

@app.route('/admin/create-admin', methods=['GET', 'POST'])
@login_required
@admin_required
def create_admin_user():
    form = CreateAdminForm()
    
    if form.validate_on_submit():
        # Create new admin user
        password_hash = generate_password_hash(form.password.data)
        new_admin = User(
            id=None,
            email=form.email.data,
            password_hash=password_hash,
            role='admin',
            created_date=datetime.now(),
            is_active=True,
            name=form.name.data,
            department=form.department.data,
            email_confirmed=False
        )
        
        try:
            new_admin.save()
            flash(f'Admin user {form.name.data} ({form.email.data}) created successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            flash('Error creating admin user. Please try again.', 'error')
            print(f'Error creating admin: {e}')
    
    return render_template('create_admin.html', form=form)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    c.execute('SELECT id, email, role, created_date, is_active, name, department, email_confirmed FROM users WHERE role = "admin" ORDER BY created_date DESC')
    admin_users = c.fetchall()
    conn.close()
    
    return render_template('admin_users.html', admin_users=admin_users)

# Public Routes
@app.route('/')
def index():
    return render_template('index.html')

# Candidate authentication removed - candidates apply directly without registration

# Public candidate application route (for non-authenticated users)
@app.route('/candidate', methods=['GET', 'POST'])
def candidate_form():
    form = CandidateForm()
    
    # Populate position_of_interest dropdown with open job positions
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    c.execute('SELECT id, position_title, job_id FROM criteria WHERE job_status = "open" ORDER BY position_title')
    open_positions = c.fetchall()
    conn.close()
    
    # Set choices for position dropdown
    if open_positions:
        form.position_of_interest.choices = [
            (str(job[0]), f"{job[1]} (ID: {job[2] or 'N/A'})")
            for job in open_positions
        ]
    else:
        form.position_of_interest.choices = [('', 'No positions available')]
    
    if form.validate_on_submit():
        # Check for duplicate candidates before processing
        conn = sqlite3.connect('candidates.db')
        c = conn.cursor()
        
        # Check for duplicate based on name, email, and position of interest
        position_id = int(form.position_of_interest.data) if form.position_of_interest.data else None
        c.execute('''
            SELECT id, name, email FROM candidates 
            WHERE LOWER(TRIM(name)) = LOWER(TRIM(?)) 
            AND LOWER(TRIM(email)) = LOWER(TRIM(?)) 
            AND position_of_interest_id = ?
        ''', (form.name.data, form.email.data, position_id))
        
        existing_candidate = c.fetchone()
        
        if existing_candidate:
            conn.close()
            # Get position title for better error message
            conn2 = sqlite3.connect('candidates.db')
            c2 = conn2.cursor()
            c2.execute('SELECT position_title FROM criteria WHERE id = ?', (position_id,))
            position_result = c2.fetchone()
            position_name = position_result[0] if position_result else 'this position'
            conn2.close()
            
            flash(f'A candidate with the name "{form.name.data}" has already applied for {position_name}. Duplicate applications are not allowed.', 'error')
            return render_template('candidate_form.html', form=form)
        
        # Save uploaded file
        file = form.resume.data
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Add position_of_interest_id column if it doesn't exist
        try:
            c.execute('SELECT position_of_interest_id FROM candidates LIMIT 1')
        except sqlite3.OperationalError:
            c.execute('ALTER TABLE candidates ADD COLUMN position_of_interest_id INTEGER')
            print("Added position_of_interest_id column to candidates table")
        
        c.execute('''INSERT INTO candidates 
                     (name, email, phone, education, education_certification, gender, position_of_interest_id,
                      experience_1, experience_1_position_title, 
                      experience_2, experience_2_position_title,
                      experience_3, experience_3_position_title,
                      experience_1_start_date, experience_1_end_date,
                      experience_2_start_date, experience_2_end_date,
                      experience_3_start_date, experience_3_end_date,
                      resume_filename)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (form.name.data, form.email.data, form.phone.data,
                   form.education.data, form.education_certification.data,
                   form.gender.data, int(form.position_of_interest.data) if form.position_of_interest.data else None,
                   form.experience_1.data, form.experience_1_position_title.data,
                   form.experience_2.data, form.experience_2_position_title.data,
                   form.experience_3.data, form.experience_3_position_title.data,
                   str(form.experience_1_start_date.data) if form.experience_1_start_date.data else '',
                   str(form.experience_1_end_date.data) if form.experience_1_end_date.data else '',
                   str(form.experience_2_start_date.data) if form.experience_2_start_date.data else '',
                   str(form.experience_2_end_date.data) if form.experience_2_end_date.data else '',
                   str(form.experience_3_start_date.data) if form.experience_3_start_date.data else '',
                   str(form.experience_3_end_date.data) if form.experience_3_end_date.data else '',
                   filename))
        
        candidate_id = c.lastrowid
        conn.commit()
        
        # Get all open job criteria for evaluation
        c.execute('SELECT * FROM criteria WHERE job_status = "open" ORDER BY created_date DESC')
        criteria_rows = c.fetchall()
        conn.close()
        
        candidate_data = {
            'name': form.name.data,
            'email': form.email.data,
            'phone': form.phone.data,
            'education': form.education.data,
            'education_certification': form.education_certification.data,
            'experience_1': form.experience_1.data,
            'experience_2': form.experience_2.data,
            'experience_3': form.experience_3.data,
            'experience_1_position_title': form.experience_1_position_title.data,
            'experience_2_position_title': form.experience_2_position_title.data,
            'experience_3_position_title': form.experience_3_position_title.data,
            'experience_1_start_date': str(form.experience_1_start_date.data) if form.experience_1_start_date.data else '',
            'experience_1_end_date': str(form.experience_1_end_date.data) if form.experience_1_end_date.data else '',
            'experience_2_start_date': str(form.experience_2_start_date.data) if form.experience_2_start_date.data else '',
            'experience_2_end_date': str(form.experience_2_end_date.data) if form.experience_2_end_date.data else '',
            'experience_3_start_date': str(form.experience_3_start_date.data) if form.experience_3_start_date.data else '',
            'experience_3_end_date': str(form.experience_3_end_date.data) if form.experience_3_end_date.data else '',
            'resume_filename': filename,
            'position_of_interest_id': int(form.position_of_interest.data) if form.position_of_interest.data else None
        }
        
        if criteria_rows:
            qualified_jobs = []
            unqualified_jobs = []
            
            # Evaluate candidate against all open job criteria
            for criteria_row in criteria_rows:
                # Handle different schema versions
                if len(criteria_row) <= 8:
                    # Old schema compatibility
                    criteria = {
                        'id': criteria_row[0],
                        'position_title': 'Legacy Position',
                        'min_experience': criteria_row[2] if len(criteria_row) > 2 else 0,
                        'min_position_years': 0,
                        'expected_positions': criteria_row[3] if len(criteria_row) > 3 else '',
                        'preferred_education': criteria_row[4] if len(criteria_row) > 4 else 'high_school',
                        'qualified_email': criteria_row[5] if len(criteria_row) > 5 else 'qualified@company.com',
                        'unqualified_email': 'unqualified@company.com'
                    }
                else:
                    # New schema structure based on actual table:
                    # [0:id, 1:min_experience, 2:required_skills, 3:preferred_education, 4:notification_email,
                    #  5:created_date, 6:is_active, 7:expected_positions, 8:position_title, 9:min_position_years,
                    #  10:qualified_email, 11:unqualified_email, 12:admin_user_id, 13:job_status, 14:required_education_certification]
                    criteria = {
                        'id': criteria_row[0],
                        'position_title': criteria_row[8] if len(criteria_row) > 8 else 'Unknown Position',
                        'min_experience': criteria_row[1] if len(criteria_row) > 1 else 0,
                        'min_position_years': criteria_row[9] if len(criteria_row) > 9 else 0,
                        'expected_positions': criteria_row[7] if len(criteria_row) > 7 else '',
                        'preferred_education': criteria_row[3] if len(criteria_row) > 3 else 'high_school',
                        'qualified_email': criteria_row[10] if len(criteria_row) > 10 else 'qualified@company.com',
                        'unqualified_email': criteria_row[11] if len(criteria_row) > 11 else 'unqualified@company.com',
                        'required_education_certification': criteria_row[14] if len(criteria_row) > 14 else ''
                    }
                
                # Check if candidate meets this job's criteria
                passed, score, max_score, feedback = check_candidate_criteria(candidate_data, criteria)
                
                if passed:
                    qualified_jobs.append((criteria, score, max_score, feedback))
                    # Send qualified notification
                    send_notification_email(candidate_data, criteria['qualified_email'], True, score, max_score, feedback, criteria['position_title'])
                else:
                    unqualified_jobs.append((criteria, score, max_score, feedback))
                    # Send unqualified notification
                    send_notification_email(candidate_data, criteria['unqualified_email'], False, score, max_score, feedback, criteria['position_title'])
            
            # Update candidate status based on overall results
            conn = sqlite3.connect('candidates.db')
            c = conn.cursor()
            
            if qualified_jobs:
                # Candidate qualified for at least one position
                c.execute('UPDATE candidates SET status = ? WHERE id = ?', ('passed', candidate_id))
                job_count = len(qualified_jobs)
                flash(f'Application submitted successfully! You qualified for {job_count} position{"s" if job_count > 1 else ""}. You will be contacted soon.', 'success')
            else:
                # Candidate didn't qualify for any positions
                c.execute('UPDATE candidates SET status = ? WHERE id = ?', ('failed', candidate_id))
                flash('Application submitted successfully! We will review your application and contact you if suitable opportunities arise.', 'info')
            
            conn.commit()
            conn.close()
        else:
            flash('Application submitted successfully! Currently, there are no active job openings, but we will keep your application on file.', 'info')
        
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
        
        # Insert new criteria based on available columns
        # Check available columns first
        c.execute("PRAGMA table_info(criteria)")
        columns = [row[1] for row in c.fetchall()]
        
        if 'qualified_email' in columns and 'unqualified_email' in columns:
            # Newer schema: include min_position_years and required_education_certification if present
            if 'min_position_years' in columns and 'required_education_certification' in columns:
                c.execute('''INSERT INTO criteria 
                             (position_title, min_experience, min_position_years, expected_positions, preferred_education, required_education_certification, qualified_email, unqualified_email)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                          (form.position_title.data, form.min_experience.data, form.min_position_years.data,
                           form.expected_positions.data, form.preferred_education.data, form.required_education_certification.data,
                           form.qualified_email.data, form.unqualified_email.data))
            elif 'min_position_years' in columns:
                c.execute('''INSERT INTO criteria 
                             (position_title, min_experience, min_position_years, expected_positions, preferred_education, qualified_email, unqualified_email)
                             VALUES (?, ?, ?, ?, ?, ?, ?)''',
                          (form.position_title.data, form.min_experience.data, form.min_position_years.data,
                           form.expected_positions.data, form.preferred_education.data,
                           form.qualified_email.data, form.unqualified_email.data))
            else:
                c.execute('''INSERT INTO criteria 
                             (position_title, min_experience, expected_positions, preferred_education, qualified_email, unqualified_email)
                             VALUES (?, ?, ?, ?, ?, ?)''',
                          (form.position_title.data, form.min_experience.data,
                           form.expected_positions.data, form.preferred_education.data, 
                           form.qualified_email.data, form.unqualified_email.data))
        else:
            # Fallback for older schema (notification_email instead of qualified/unqualified)
            if 'min_position_years' in columns:
                c.execute('''INSERT INTO criteria 
                             (position_title, min_experience, min_position_years, expected_positions, preferred_education, notification_email)
                             VALUES (?, ?, ?, ?, ?, ?)''',
                          (form.position_title.data, form.min_experience.data, form.min_position_years.data,
                           form.expected_positions.data, form.preferred_education.data, 
                           form.qualified_email.data))  # Use qualified_email as fallback for notification
            else:
                c.execute('''INSERT INTO criteria 
                             (position_title, min_experience, expected_positions, preferred_education, notification_email)
                             VALUES (?, ?, ?, ?, ?)''',
                          (form.position_title.data, form.min_experience.data,
                           form.expected_positions.data, form.preferred_education.data, 
                           form.qualified_email.data))  # Use qualified_email as fallback
        
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
        # Check if this is old schema (fewer fields) or new schema
        if len(current_criteria) <= 8:  # Old schema has 8 fields or less
            # Old schema: [id, admin_user_id, min_experience, required_skills, preferred_education, notification_email, created_date, is_active]
            form.position_title.data = 'Legacy Position'  # Default value
            form.min_experience.data = current_criteria[2] if len(current_criteria) > 2 else 0
            form.min_position_years.data = 0  # Default value
            form.expected_positions.data = current_criteria[3] if len(current_criteria) > 3 else ''
            form.preferred_education.data = current_criteria[4] if len(current_criteria) > 4 else 'high_school'
            form.qualified_email.data = current_criteria[5] if len(current_criteria) > 5 else 'qualified@company.com'
            form.unqualified_email.data = 'unqualified@company.com'  # Default value
        else:  # Actual table structure based on debug output
            # Actual structure: [id, min_experience, required_skills, preferred_education, notification_email, created_date, is_active, expected_positions, position_title, min_position_years, qualified_email, unqualified_email, admin_user_id, job_status, required_education_certification]
            form.position_title.data = current_criteria[8]  # position_title at index 8
            form.min_experience.data = current_criteria[1]  # min_experience at index 1
            form.min_position_years.data = current_criteria[9]  # min_position_years at index 9
            form.expected_positions.data = current_criteria[7] if current_criteria[7] else ''  # expected_positions at index 7
            form.preferred_education.data = current_criteria[3]  # preferred_education at index 3
            form.qualified_email.data = current_criteria[10]  # qualified_email at index 10
            form.unqualified_email.data = current_criteria[11]  # unqualified_email at index 11
            # Handle required_education_certification if present (index 14)
            if len(current_criteria) > 14:
                form.required_education_certification.data = current_criteria[14] if current_criteria[14] else ''

    # Build a normalized display object for the template so indices don't get mixed up
    current_criteria_display = None
    if current_criteria:
        if len(current_criteria) <= 8:
            # Old schema mapping
            current_criteria_display = {
                'position_title': 'Legacy Position',
                'min_experience': current_criteria[2] if len(current_criteria) > 2 else 0,
                'min_position_years': 0,
                'expected_positions': current_criteria[3] if len(current_criteria) > 3 else '',
                'preferred_education': str(current_criteria[4]) if len(current_criteria) > 4 and current_criteria[4] else 'high_school',
                'required_education_certification': '',  # Not available in old schema
                'qualified_email': current_criteria[5] if len(current_criteria) > 5 else 'qualified@company.com',
                'unqualified_email': 'unqualified@company.com',
                'created_date': current_criteria[6] if len(current_criteria) > 6 else None,
            }
        else:
            # Actual table structure based on debug:
            # 0: id, 1: min_experience, 2: required_skills, 3: preferred_education, 4: notification_email,
            # 5: created_date, 6: is_active, 7: expected_positions, 8: position_title, 9: min_position_years,
            # 10: qualified_email, 11: unqualified_email, 12: admin_user_id, 13: job_status, 14: required_education_certification
            current_criteria_display = {
                'position_title': str(current_criteria[8]) if current_criteria[8] else 'Unknown Position',
                'min_experience': current_criteria[1] if current_criteria[1] is not None else 0,
                'min_position_years': current_criteria[9] if current_criteria[9] is not None else 0,
                'expected_positions': str(current_criteria[7]) if current_criteria[7] else '',
                'preferred_education': str(current_criteria[3]) if current_criteria[3] else 'high_school',
                'required_education_certification': str(current_criteria[14]) if len(current_criteria) > 14 and current_criteria[14] else '',
                'qualified_email': str(current_criteria[10]) if current_criteria[10] else 'qualified@company.com',
                'unqualified_email': str(current_criteria[11]) if current_criteria[11] else 'unqualified@company.com',
                'created_date': current_criteria[5] if len(current_criteria) > 5 else None,
            }

    return render_template('admin_form.html', form=form, current_criteria=current_criteria, current_criteria_display=current_criteria_display)

# New Job Management Routes
@app.route('/admin/jobs')
@login_required
@admin_required
def manage_jobs():
    """Display all job criteria with management options"""
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    
    # Get all job criteria with admin info
    c.execute('''SELECT c.*, u.email as admin_email, u.name as admin_name 
                 FROM criteria c 
                 LEFT JOIN users u ON c.admin_user_id = u.id 
                 ORDER BY c.created_date DESC''')
    jobs = c.fetchall()
    
    # Get counts by status
    c.execute('SELECT job_status, COUNT(*) FROM criteria GROUP BY job_status')
    status_counts = dict(c.fetchall())
    
    conn.close()
    
    return render_template('manage_jobs.html', jobs=jobs, status_counts=status_counts)

@app.route('/admin/jobs/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_job():
    """Add new job criteria"""
    form = AdminCriteriaForm()
    
    if form.validate_on_submit():
        conn = sqlite3.connect('candidates.db')
        c = conn.cursor()
        
        # Check available columns
        c.execute("PRAGMA table_info(criteria)")
        columns = [row[1] for row in c.fetchall()]
        
        # Generate unique job ID
        job_id = generate_unique_job_id(c)
        
        # Insert new job criteria with job_status and job_id
        if 'job_status' in columns and 'required_education_certification' in columns and 'job_id' in columns:
            c.execute('''INSERT INTO criteria 
                         (admin_user_id, position_title, min_experience, min_position_years, 
                          expected_positions, preferred_education, required_education_certification, 
                          qualified_email, unqualified_email, job_status, job_id)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (current_user.id, form.position_title.data, form.min_experience.data, 
                       form.min_position_years.data, form.expected_positions.data, 
                       form.preferred_education.data, form.required_education_certification.data,
                       form.qualified_email.data, form.unqualified_email.data, form.job_status.data, job_id))
        elif 'job_status' in columns and 'job_id' in columns:
            c.execute('''INSERT INTO criteria 
                         (admin_user_id, position_title, min_experience, min_position_years, 
                          expected_positions, preferred_education, qualified_email, unqualified_email, job_status, job_id)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (current_user.id, form.position_title.data, form.min_experience.data, 
                       form.min_position_years.data, form.expected_positions.data, 
                       form.preferred_education.data, form.qualified_email.data, 
                       form.unqualified_email.data, form.job_status.data, job_id))
        elif 'job_id' in columns:
            # Fallback with job_id but older schema
            c.execute('''INSERT INTO criteria 
                         (admin_user_id, position_title, min_experience, min_position_years, 
                          expected_positions, preferred_education, qualified_email, unqualified_email, job_id)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (current_user.id, form.position_title.data, form.min_experience.data, 
                       form.min_position_years.data, form.expected_positions.data, 
                       form.preferred_education.data, form.qualified_email.data, 
                       form.unqualified_email.data, job_id))
        else:
            # Fallback for oldest schema without job_id
            c.execute('''INSERT INTO criteria 
                         (admin_user_id, position_title, min_experience, min_position_years, 
                          expected_positions, preferred_education, qualified_email, unqualified_email)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                      (current_user.id, form.position_title.data, form.min_experience.data, 
                       form.min_position_years.data, form.expected_positions.data, 
                       form.preferred_education.data, form.qualified_email.data, 
                       form.unqualified_email.data))
        
        conn.commit()
        conn.close()
        
        flash(f'Job criteria for "{form.position_title.data}" (ID: {job_id}) added successfully!', 'success')
        return redirect(url_for('manage_jobs'))
    
    return render_template('add_job.html', form=form)

@app.route('/admin/jobs/edit/<int:job_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_job(job_id):
    """Edit existing job criteria"""
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    c.execute('SELECT * FROM criteria WHERE id = ?', (job_id,))
    job = c.fetchone()
    
    if not job:
        flash('Job criteria not found.', 'error')
        return redirect(url_for('manage_jobs'))
    
    form = EditJobForm()
    
    if form.validate_on_submit():
        # Check if required_education_certification column exists
        c.execute("PRAGMA table_info(criteria)")
        columns = [row[1] for row in c.fetchall()]
        
        # Update job criteria with or without required_education_certification
        if 'required_education_certification' in columns:
            c.execute('''UPDATE criteria SET 
                         position_title=?, min_experience=?, min_position_years=?, 
                         expected_positions=?, preferred_education=?, required_education_certification=?,
                         qualified_email=?, unqualified_email=?, job_status=?
                         WHERE id=?''',
                      (form.position_title.data, form.min_experience.data, form.min_position_years.data,
                       form.expected_positions.data, form.preferred_education.data, form.required_education_certification.data,
                       form.qualified_email.data, form.unqualified_email.data, form.job_status.data, job_id))
        else:
            c.execute('''UPDATE criteria SET 
                         position_title=?, min_experience=?, min_position_years=?, 
                         expected_positions=?, preferred_education=?, qualified_email=?, 
                         unqualified_email=?, job_status=?
                         WHERE id=?''',
                      (form.position_title.data, form.min_experience.data, form.min_position_years.data,
                       form.expected_positions.data, form.preferred_education.data, form.qualified_email.data,
                       form.unqualified_email.data, form.job_status.data, job_id))
        
        conn.commit()
        conn.close()
        
        flash(f'Job criteria "{form.position_title.data}" updated successfully!', 'success')
        return redirect(url_for('manage_jobs'))
    
    # Pre-fill form with current data based on actual schema
    # Schema: [id, min_experience, required_skills, preferred_education, notification_email, 
    #          created_date, is_active, expected_positions, position_title, min_position_years,
    #          qualified_email, unqualified_email, admin_user_id, job_status, required_education_certification]
    if len(job) > 13:  # Current schema
        form.position_title.data = job[8] if job[8] else ''
        form.min_experience.data = job[1] if job[1] is not None else 0
        form.min_position_years.data = job[9] if job[9] is not None else 0
        form.expected_positions.data = job[7] if job[7] else ''
        form.preferred_education.data = job[3] if job[3] else 'high_school'
        form.qualified_email.data = job[10] if job[10] else ''
        form.unqualified_email.data = job[11] if job[11] else ''
        form.job_status.data = job[13] if job[13] else 'open'
        # Handle required_education_certification if present (index 14)
        if len(job) > 14:
            form.required_education_certification.data = job[14] if job[14] else ''
    
    conn.close()
    return render_template('edit_job.html', form=form, job=job)

@app.route('/admin/jobs/toggle/<int:job_id>', methods=['POST'])
@login_required
@admin_required
def toggle_job_status(job_id):
    """Toggle job status between open and closed"""
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    
    # Get current status
    c.execute('SELECT job_status FROM criteria WHERE id = ?', (job_id,))
    result = c.fetchone()
    
    if not result:
        flash('Job not found.', 'error')
        return redirect(url_for('manage_jobs'))
    
    current_status = result[0]
    new_status = 'closed' if current_status == 'open' else 'open'
    
    # Update status
    c.execute('UPDATE criteria SET job_status = ? WHERE id = ?', (new_status, job_id))
    conn.commit()
    conn.close()
    
    flash(f'Job status changed to {new_status.upper()}.', 'success')
    return redirect(url_for('manage_jobs'))

@app.route('/admin/jobs/clear', methods=['GET', 'POST'])
@login_required
@admin_required
def clear_jobs():
    """Clear job criteria based on selection"""
    form = BulkClearForm()
    
    if form.validate_on_submit():
        conn = sqlite3.connect('candidates.db')
        c = conn.cursor()
        
        clear_type = form.clear_type.data
        deleted_count = 0
        
        if clear_type == 'all':
            c.execute('DELETE FROM criteria')
            deleted_count = c.rowcount
            flash(f'All {deleted_count} job criteria cleared successfully!', 'success')
        elif clear_type == 'closed':
            c.execute('DELETE FROM criteria WHERE job_status = "closed"')
            deleted_count = c.rowcount
            flash(f'{deleted_count} closed job criteria cleared successfully!', 'success')
        elif clear_type == 'specific':
            # This would be handled by a separate form with checkboxes
            # For now, redirect to manage page for manual selection
            flash('Specific job clearing requires manual selection from the job management page.', 'info')
            return redirect(url_for('manage_jobs'))
        
        conn.commit()
        conn.close()
        
        return redirect(url_for('manage_jobs'))
    
    return render_template('clear_jobs.html', form=form)

@app.route('/admin/jobs/download/<int:job_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def download_job_resumes(job_id):
    """Download resumes for candidates of a specific job"""
    import zipfile
    from io import BytesIO
    from flask import send_file
    
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    
    # Get job details
    c.execute('SELECT position_title FROM criteria WHERE id = ?', (job_id,))
    job_result = c.fetchone()
    
    if not job_result:
        flash('Job not found.', 'error')
        return redirect(url_for('manage_jobs'))
    
    job_title = job_result[0]
    
    if request.method == 'GET':
        # Get candidates count by status for this job
        c.execute('''
            SELECT status, COUNT(*) 
            FROM candidates 
            WHERE position_of_interest_id = ? AND resume_filename IS NOT NULL AND resume_filename != ''
            GROUP BY status
        ''', (job_id,))
        status_counts = dict(c.fetchall())
        conn.close()
        
        return render_template('download_resumes.html', 
                             job_id=job_id, 
                             job_title=job_title, 
                             status_counts=status_counts)
    
    elif request.method == 'POST':
        download_passed = 'passed' in request.form
        download_failed = 'failed' in request.form
        
        if not download_passed and not download_failed:
            flash('Please select at least one status to download.', 'warning')
            return redirect(url_for('download_job_resumes', job_id=job_id))
        
        # Build query based on selected statuses
        status_conditions = []
        if download_passed:
            status_conditions.append("'passed'")
        if download_failed:
            status_conditions.append("'failed'")
        
        query = f'''
            SELECT name, resume_filename, status 
            FROM candidates 
            WHERE position_of_interest_id = ? 
            AND status IN ({','.join(status_conditions)})
            AND resume_filename IS NOT NULL 
            AND resume_filename != ''
            ORDER BY status, name
        '''
        
        c.execute(query, (job_id,))
        candidates = c.fetchall()
        conn.close()
        
        if not candidates:
            flash('No resumes found for the selected criteria.', 'info')
            return redirect(url_for('download_job_resumes', job_id=job_id))
        
        # Create a zip file in memory
        zip_buffer = BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for candidate_name, resume_filename, status in candidates:
                resume_path = os.path.join(app.config['UPLOAD_FOLDER'], resume_filename)
                
                if os.path.exists(resume_path):
                    # Create folder structure: Status/candidate_name_resume.ext
                    file_extension = os.path.splitext(resume_filename)[1]
                    safe_name = "".join(c for c in candidate_name if c.isalnum() or c in (' ', '-', '_')).strip()
                    archive_filename = f"{status.upper()}/{safe_name}_resume{file_extension}"
                    
                    zip_file.write(resume_path, archive_filename)
        
        zip_buffer.seek(0)
        
        # Create a safe filename for the zip
        safe_job_title = "".join(c for c in job_title if c.isalnum() or c in (' ', '-', '_')).strip()
        status_suffix = []
        if download_passed:
            status_suffix.append('PASSED')
        if download_failed:
            status_suffix.append('FAILED')
        
        zip_filename = f"{safe_job_title}_resumes_{'_'.join(status_suffix)}.zip"
        
        flash(f'Downloaded {len(candidates)} resumes for job "{job_title}".', 'success')
        
        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name=zip_filename,
            mimetype='application/zip'
        )

@app.route('/admin/jobs/delete/<int:job_id>', methods=['POST'])
@login_required
@admin_required
def delete_job(job_id):
    """Delete specific job criteria"""
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    
    # Get job title for confirmation message
    c.execute('SELECT position_title FROM criteria WHERE id = ?', (job_id,))
    result = c.fetchone()
    
    if not result:
        flash('Job not found.', 'error')
        return redirect(url_for('manage_jobs'))
    
    job_title = result[0]
    
    # Delete the job
    c.execute('DELETE FROM criteria WHERE id = ?', (job_id,))
    conn.commit()
    conn.close()
    
    flash(f'Job criteria "{job_title}" deleted successfully!', 'success')
    return redirect(url_for('manage_jobs'))

@app.route('/admin/jobs/status', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_job_status():
    """Dedicated page for managing job statuses with toggle and clear options"""
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    
    # Handle POST requests for status changes and clearing
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'toggle_status':
            job_id = request.form.get('job_id')
            if job_id:
                # Get current status
                c.execute('SELECT job_status, position_title FROM criteria WHERE id = ?', (job_id,))
                result = c.fetchone()
                
                if result:
                    current_status, position_title = result
                    new_status = 'closed' if current_status == 'open' else 'open'
                    
                    # Update status
                    c.execute('UPDATE criteria SET job_status = ? WHERE id = ?', (new_status, job_id))
                    conn.commit()
                    
                    flash(f'Job "{position_title}" status changed to {new_status.upper()}.', 'success')
                else:
                    flash('Job not found.', 'error')
        
        elif action == 'clear_closed':
            c.execute('DELETE FROM criteria WHERE job_status = "closed"')
            deleted_count = c.rowcount
            conn.commit()
            flash(f'{deleted_count} closed job criteria cleared successfully!', 'success')
        
        elif action == 'clear_all':
            c.execute('DELETE FROM criteria')
            deleted_count = c.rowcount
            conn.commit()
            flash(f'All {deleted_count} job criteria cleared successfully!', 'warning')
    
    # Get all job criteria with counts
    c.execute('''SELECT * FROM criteria ORDER BY 
                 CASE WHEN job_status = 'open' THEN 0 ELSE 1 END, 
                 created_date DESC''')
    jobs = c.fetchall()
    
    # Get status counts
    c.execute('SELECT job_status, COUNT(*) FROM criteria GROUP BY job_status')
    status_counts = dict(c.fetchall())
    
    conn.close()
    
    return render_template('manage_job_status.html', jobs=jobs, status_counts=status_counts)

@app.route('/admin/candidates')
@login_required
@admin_required
def view_candidates():
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    
    # Ensure position_of_interest_id column exists
    try:
        c.execute('SELECT position_of_interest_id FROM candidates LIMIT 1')
    except sqlite3.OperationalError:
        c.execute('ALTER TABLE candidates ADD COLUMN position_of_interest_id INTEGER')
        print("Added position_of_interest_id column to candidates table")
        conn.commit()
    
    # Get filter parameters
    job_filter = request.args.get('job_id', '')
    status_filter = request.args.get('status', '')
    job_status_filter = request.args.get('job_status', '')  # New filter for job position summaries
    
    # Get only open job criteria for the dropdown filter
    c.execute('SELECT id, position_title FROM criteria WHERE job_status = "open" ORDER BY position_title')
    job_criteria = c.fetchall()
    
    # Build the main query with joins
    base_query = '''
        SELECT 
            c.id, c.name, c.email, c.phone, c.education, 
            c.status, c.submission_date, c.resume_filename,
            c.experience_1, c.experience_2, c.experience_3,
            c.position_of_interest_id,
            cr.position_title as applied_position,
            cr.id as criteria_id,
            c.experience_1_position_title, c.experience_2_position_title, c.experience_3_position_title
        FROM candidates c
        LEFT JOIN criteria cr ON c.position_of_interest_id = cr.id
    '''
    
    conditions = []
    params = []
    
    # Apply filters
    if job_filter:
        conditions.append('c.position_of_interest_id = ?')
        params.append(job_filter)
    
    if status_filter:
        conditions.append('c.status = ?')
        params.append(status_filter)
    
    # Add WHERE clause if there are conditions
    if conditions:
        base_query += ' WHERE ' + ' AND '.join(conditions)
    
    base_query += ' ORDER BY c.submission_date DESC'
    
    c.execute(base_query, params)
    candidates = c.fetchall()
    
    # Get candidates grouped by job position for summary with job status filter
    summary_query = '''
        SELECT 
            cr.position_title,
            cr.id as criteria_id,
            COUNT(c.id) as total_applications,
            SUM(CASE WHEN c.status = 'passed' THEN 1 ELSE 0 END) as passed_count,
            SUM(CASE WHEN c.status = 'failed' THEN 1 ELSE 0 END) as failed_count,
            SUM(CASE WHEN c.status = 'pending' THEN 1 ELSE 0 END) as pending_count,
            cr.job_status
        FROM criteria cr
        LEFT JOIN candidates c ON c.position_of_interest_id = cr.id
    '''
    
    # Add job status filter for summaries
    summary_conditions = []
    summary_params = []
    
    if job_status_filter:
        summary_conditions.append('cr.job_status = ?')
        summary_params.append(job_status_filter)
    
    if summary_conditions:
        summary_query += ' WHERE ' + ' AND '.join(summary_conditions)
    
    summary_query += ' GROUP BY cr.id, cr.position_title, cr.job_status ORDER BY cr.position_title'
    
    c.execute(summary_query, summary_params)
    job_summaries = c.fetchall()
    
    # Get overall statistics
    c.execute('''
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status = 'passed' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending
        FROM candidates
    ''')
    overall_stats = c.fetchone()
    
    conn.close()
    
    return render_template('candidates_segmented.html', 
                         candidates=candidates,
                         job_criteria=job_criteria,
                         job_summaries=job_summaries,
                         overall_stats=overall_stats,
                         current_job_filter=job_filter,
                         current_status_filter=status_filter,
                         current_job_status_filter=job_status_filter)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
