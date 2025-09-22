"""
Standalone API for Vercel Deployment
This version doesn't depend on the main app.py file
"""

import os
from datetime import datetime
from flask import Flask, jsonify, request

# Create Flask app
app = Flask(__name__)
app.config.update({
    'SECRET_KEY': os.environ.get('SECRET_KEY', 'vercel-secret-key'),
    'DEBUG': False,
})

# Simple CORS headers (instead of flask-cors)
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Simple in-memory data for demo (since SQLite won't persist on Vercel)
sample_data = {
    'candidates': [
        {
            'id': 1,
            'name': 'John Doe',
            'email': 'john@example.com',
            'status': 'pending',
            'submission_date': '2024-01-15T10:00:00'
        },
        {
            'id': 2,
            'name': 'Jane Smith',
            'email': 'jane@example.com',
            'status': 'passed',
            'submission_date': '2024-01-14T09:30:00'
        }
    ],
    'jobs': [
        {
            'id': 1,
            'position_title': 'Software Engineer',
            'job_status': 'open',
            'total_applications': 5,
            'passed_count': 2,
            'failed_count': 1,
            'pending_count': 2
        }
    ]
}

@app.route('/')
def home():
    """Root endpoint"""
    return jsonify({
        'message': 'Candidate Filtration System API',
        'status': 'online',
        'version': '1.0.0',
        'endpoints': ['/health', '/api/version', '/api/candidates', '/api/jobs', '/api/stats']
    })

@app.route('/health')
@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'service': 'candidate-filtration-system',
        'platform': 'vercel'
    })

@app.route('/api/version')
def api_version():
    """API version information"""
    return jsonify({
        'version': '1.0.0',
        'name': 'Candidate Filtration System API',
        'description': 'API for managing candidate applications and job criteria',
        'platform': 'Vercel Serverless',
        'endpoints': {
            'health': '/health or /api/health',
            'version': '/api/version',
            'candidates': '/api/candidates',
            'jobs': '/api/jobs',
            'stats': '/api/stats'
        },
        'limitations': [
            'No persistent database (demo data only)',
            'No file uploads',
            '10-second function timeout'
        ]
    })

@app.route('/api/candidates')
def api_get_candidates():
    """Get all candidates"""
    try:
        status_filter = request.args.get('status')
        candidates = sample_data['candidates']
        
        if status_filter:
            candidates = [c for c in candidates if c['status'] == status_filter]
        
        return jsonify({
            'success': True,
            'count': len(candidates),
            'candidates': candidates,
            'note': 'This is demo data - Vercel does not support persistent SQLite databases'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/jobs')
def api_get_jobs():
    """Get all job positions"""
    try:
        jobs = sample_data['jobs']
        
        return jsonify({
            'success': True,
            'count': len(jobs),
            'jobs': jobs,
            'note': 'This is demo data - Vercel does not support persistent SQLite databases'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stats')
def api_get_stats():
    """Get system statistics"""
    try:
        candidates = sample_data['candidates']
        jobs = sample_data['jobs']
        
        # Calculate stats from sample data
        total_candidates = len(candidates)
        passed_candidates = len([c for c in candidates if c['status'] == 'passed'])
        failed_candidates = len([c for c in candidates if c['status'] == 'failed'])
        pending_candidates = len([c for c in candidates if c['status'] == 'pending'])
        
        return jsonify({
            'success': True,
            'statistics': {
                'candidates': {
                    'total': total_candidates,
                    'passed': passed_candidates,
                    'failed': failed_candidates,
                    'pending': pending_candidates
                },
                'jobs': {
                    'total': len(jobs),
                    'open': len([j for j in jobs if j['job_status'] == 'open']),
                    'closed': len([j for j in jobs if j['job_status'] == 'closed'])
                }
            },
            'timestamp': datetime.now().isoformat(),
            'note': 'This is demo data - Vercel does not support persistent SQLite databases'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Vercel handler
handler = app

if __name__ == '__main__':
    app.run(debug=True)
