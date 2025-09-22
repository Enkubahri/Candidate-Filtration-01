"""
API Entry Point for Candidate Filtration System
Deployment-ready Flask application for test server
"""

import os
import sys
import sqlite3
from datetime import datetime

# Add the parent directory to Python path to import the main app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request, render_template
from flask_cors import CORS

# Import the main application components
try:
    from app import app as main_app, init_db, User
    from app import (
        CandidateForm, AdminCriteriaForm, LoginForm, RegisterForm,
        extract_text_from_pdf, extract_text_from_docx, 
        calculate_total_years, process_candidate_application,
        generate_unique_job_id
    )
except ImportError as e:
    print(f"Import error: {e}")
    # Create a minimal Flask app if imports fail
    main_app = Flask(__name__)
    main_app.config['SECRET_KEY'] = 'fallback-secret-key'

# Configure the app for deployment
app = main_app
app.config.update({
    'SECRET_KEY': os.environ.get('SECRET_KEY', 'your-production-secret-key'),
    'DEBUG': os.environ.get('FLASK_ENV') == 'development',
    'UPLOAD_FOLDER': os.environ.get('UPLOAD_FOLDER', 'uploads'),
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB max file size
    'DATABASE_URL': os.environ.get('DATABASE_URL', 'candidates.db')
})

# Enable CORS for cross-origin requests
CORS(app)

# Health check endpoint for deployment
@app.route('/health')
@app.route('/api/health')
def health_check():
    """Health check endpoint for deployment monitoring"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'service': 'candidate-filtration-system'
    })

# API version endpoint
@app.route('/api/version')
def api_version():
    """API version information"""
    return jsonify({
        'version': '1.0.0',
        'name': 'Candidate Filtration System API',
        'description': 'API for managing candidate applications and job criteria',
        'endpoints': {
            'health': '/health or /api/health',
            'version': '/api/version',
            'candidates': '/api/candidates',
            'jobs': '/api/jobs',
            'stats': '/api/stats'
        }
    })

# API endpoint to get all candidates
@app.route('/api/candidates')
def api_get_candidates():
    """Get all candidates with optional filtering"""
    try:
        conn = sqlite3.connect(app.config['DATABASE_URL'])
        c = conn.cursor()
        
        # Optional filters
        status = request.args.get('status')
        job_id = request.args.get('job_id')
        
        query = '''
            SELECT c.*, cr.position_title, cr.job_id
            FROM candidates c
            LEFT JOIN criteria cr ON c.position_of_interest_id = cr.id
        '''
        
        conditions = []
        params = []
        
        if status:
            conditions.append('c.status = ?')
            params.append(status)
        
        if job_id:
            conditions.append('cr.job_id = ?')
            params.append(job_id)
        
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        
        query += ' ORDER BY c.submission_date DESC'
        
        c.execute(query, params)
        candidates = c.fetchall()
        
        # Convert to list of dictionaries
        columns = [description[0] for description in c.description]
        candidates_list = [dict(zip(columns, candidate)) for candidate in candidates]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'count': len(candidates_list),
            'candidates': candidates_list
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# API endpoint to get all job criteria
@app.route('/api/jobs')
def api_get_jobs():
    """Get all job criteria/positions"""
    try:
        conn = sqlite3.connect(app.config['DATABASE_URL'])
        c = conn.cursor()
        
        status_filter = request.args.get('status', 'open')
        
        query = '''
            SELECT cr.*, u.name as admin_name, u.email as admin_email,
                   COUNT(c.id) as total_applications,
                   SUM(CASE WHEN c.status = 'passed' THEN 1 ELSE 0 END) as passed_count,
                   SUM(CASE WHEN c.status = 'failed' THEN 1 ELSE 0 END) as failed_count,
                   SUM(CASE WHEN c.status = 'pending' THEN 1 ELSE 0 END) as pending_count
            FROM criteria cr
            LEFT JOIN users u ON cr.admin_user_id = u.id
            LEFT JOIN candidates c ON c.position_of_interest_id = cr.id
        '''
        
        params = []
        if status_filter:
            query += ' WHERE cr.job_status = ?'
            params.append(status_filter)
        
        query += ' GROUP BY cr.id ORDER BY cr.created_date DESC'
        
        c.execute(query, params)
        jobs = c.fetchall()
        
        # Convert to list of dictionaries
        columns = [description[0] for description in c.description]
        jobs_list = [dict(zip(columns, job)) for job in jobs]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'count': len(jobs_list),
            'jobs': jobs_list
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# API endpoint for system statistics
@app.route('/api/stats')
def api_get_stats():
    """Get system statistics"""
    try:
        conn = sqlite3.connect(app.config['DATABASE_URL'])
        c = conn.cursor()
        
        # Overall candidate statistics
        c.execute('''
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'passed' THEN 1 ELSE 0 END) as passed,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending
            FROM candidates
        ''')
        candidate_stats = c.fetchone()
        
        # Job statistics
        c.execute('''
            SELECT 
                COUNT(*) as total_jobs,
                SUM(CASE WHEN job_status = 'open' THEN 1 ELSE 0 END) as open_jobs,
                SUM(CASE WHEN job_status = 'closed' THEN 1 ELSE 0 END) as closed_jobs
            FROM criteria
        ''')
        job_stats = c.fetchone()
        
        # User statistics
        c.execute('''
            SELECT 
                COUNT(*) as total_users,
                SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as admin_users,
                SUM(CASE WHEN role = 'candidate' THEN 1 ELSE 0 END) as candidate_users
            FROM users
        ''')
        user_stats = c.fetchone()
        
        conn.close()
        
        return jsonify({
            'success': True,
            'statistics': {
                'candidates': {
                    'total': candidate_stats[0],
                    'passed': candidate_stats[1],
                    'failed': candidate_stats[2],
                    'pending': candidate_stats[3]
                },
                'jobs': {
                    'total': job_stats[0],
                    'open': job_stats[1],
                    'closed': job_stats[2]
                },
                'users': {
                    'total': user_stats[0],
                    'admins': user_stats[1],
                    'candidates': user_stats[2]
                }
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Initialize database on startup
def initialize_app():
    """Initialize the application and database"""
    try:
        # Ensure upload directory exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Initialize database
        init_db()
        print("Database initialized successfully")
        
    except Exception as e:
        print(f"Error initializing app: {e}")

# For production deployment (Gunicorn, uWSGI, etc.)
def create_app():
    """Application factory for production deployment"""
    initialize_app()
    return app

# Development server
if __name__ == '__main__':
    initialize_app()
    
    # Get configuration from environment variables
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"Starting Candidate Filtration System API...")
    print(f"Server: http://{host}:{port}")
    print(f"Health check: http://{host}:{port}/health")
    print(f"API docs: http://{host}:{port}/api/version")
    
    app.run(host=host, port=port, debug=debug)
