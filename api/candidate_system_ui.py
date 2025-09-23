from http.server import BaseHTTPRequestHandler
import json
import os
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import re

class handler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Sample candidate data (in a real app, this would come from a database)
        self.sample_candidates = [
            {
                "id": 1,
                "name": "Alice Johnson",
                "email": "alice@example.com",
                "phone": "+1-555-0101",
                "experience_years": 5,
                "position_experience_years": 3,
                "education": "master",
                "education_certification": "Computer Science",
                "gender": "female",
                "skills": ["Python", "SQL", "JavaScript", "React", "AWS"],
                "experience_positions": [
                    {"title": "Senior Developer", "duration": "2021-2024"},
                    {"title": "Software Engineer", "duration": "2019-2021"},
                    {"title": "Junior Developer", "duration": "2017-2019"}
                ],
                "status": "passed",
                "submission_date": "2024-01-15T10:30:00",
                "score": 85
            },
            {
                "id": 2,
                "name": "Bob Smith",
                "email": "bob@example.com", 
                "phone": "+1-555-0102",
                "experience_years": 2,
                "position_experience_years": 1,
                "education": "bachelor",
                "education_certification": "Information Technology",
                "gender": "male",
                "skills": ["HTML", "CSS", "JavaScript"],
                "experience_positions": [
                    {"title": "Web Developer", "duration": "2022-2024"},
                    {"title": "Intern Developer", "duration": "2021-2022"}
                ],
                "status": "failed",
                "submission_date": "2024-01-14T09:15:00",
                "score": 45
            },
            {
                "id": 3,
                "name": "Carol Davis",
                "email": "carol@example.com",
                "phone": "+1-555-0103", 
                "experience_years": 7,
                "position_experience_years": 5,
                "education": "phd",
                "education_certification": "Software Engineering",
                "gender": "female",
                "skills": ["Python", "Java", "Machine Learning", "Docker", "Kubernetes"],
                "experience_positions": [
                    {"title": "Lead Engineer", "duration": "2020-2024"},
                    {"title": "Senior Developer", "duration": "2018-2020"},
                    {"title": "Software Engineer", "duration": "2016-2018"}
                ],
                "status": "passed",
                "submission_date": "2024-01-13T14:20:00",
                "score": 95
            },
            {
                "id": 4,
                "name": "David Wilson",
                "email": "david@example.com",
                "phone": "+1-555-0104",
                "experience_years": 3,
                "position_experience_years": 2,
                "education": "bachelor",
                "education_certification": "Computer Engineering", 
                "gender": "male",
                "skills": ["Java", "Spring", "SQL", "Git"],
                "experience_positions": [
                    {"title": "Backend Developer", "duration": "2022-2024"},
                    {"title": "Junior Developer", "duration": "2020-2022"}
                ],
                "status": "pending",
                "submission_date": "2024-01-16T11:45:00",
                "score": None
            }
        ]
        
        # Sample job criteria
        self.job_criteria = [
            {
                "id": 1,
                "job_id": 1001,
                "position_title": "Senior Software Engineer",
                "min_experience": 3,
                "min_position_years": 2,
                "required_skills": ["Python", "SQL", "JavaScript"],
                "expected_positions": ["Senior Developer", "Software Engineer", "Lead Engineer"],
                "preferred_education": "bachelor",
                "required_education_certification": "Computer Science",
                "job_status": "open",
                "created_date": "2024-01-10T09:00:00",
                "total_applications": 4,
                "passed_count": 2,
                "failed_count": 1,
                "pending_count": 1
            },
            {
                "id": 2,
                "job_id": 1002,
                "position_title": "Frontend Developer",
                "min_experience": 2,
                "min_position_years": 1,
                "required_skills": ["JavaScript", "React", "CSS"],
                "expected_positions": ["Frontend Developer", "Web Developer", "UI Developer"],
                "preferred_education": "associate",
                "required_education_certification": "Web Development",
                "job_status": "closed",
                "created_date": "2024-01-05T10:30:00",
                "total_applications": 8,
                "passed_count": 3,
                "failed_count": 4,
                "pending_count": 1
            }
        ]
        
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        try:
            # Parse the URL
            url_parts = urlparse(self.path)
            path = url_parts.path.rstrip('/')
            query_params = parse_qs(url_parts.query)
            
            # Handle HTML pages vs API endpoints
            if path.startswith('/api/'):
                self.handle_api_request(path, query_params)
            else:
                self.handle_html_request(path, query_params)
            
        except Exception as e:
            self.send_error_response(str(e))
    
    def handle_html_request(self, path, query_params):
        """Handle HTML page requests"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        if path == '' or path == '/':
            html = self.get_dashboard_html()
        elif path == '/candidates':
            html = self.get_candidates_html()
        elif path == '/jobs':
            html = self.get_jobs_html()
        elif path == '/stats':
            html = self.get_stats_html()
        elif path == '/filter':
            html = self.get_filter_html()
        else:
            html = self.get_404_html()
        
        self.wfile.write(html.encode('utf-8'))
    
    def handle_api_request(self, path, query_params):
        """Handle API requests (JSON responses)"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        self.end_headers()
        
        if path == '/api/health':
            response = self.health_endpoint()
        elif path == '/api/version':
            response = self.version_endpoint()
        elif path == '/api/candidates':
            response = self.candidates_endpoint(query_params)
        elif path == '/api/jobs':
            response = self.jobs_endpoint(query_params)
        elif path == '/api/stats':
            response = self.stats_endpoint()
        elif path == '/api/filter':
            response = self.filter_endpoint(query_params)
        else:
            response = self.not_found_endpoint()
        
        self.wfile.write(json.dumps(response, indent=2, default=str).encode())
    
    def get_dashboard_html(self):
        """Main dashboard HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Candidate Filtration System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .hero-section {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 60px 0;
        }
        .feature-card {
            transition: transform 0.2s;
            height: 100%;
        }
        .feature-card:hover {
            transform: translateY(-5px);
        }
        .stats-card {
            background: linear-gradient(45deg, #f093fb 0%, #f5576c 100%);
            color: white;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/"><i class="fas fa-users-cog"></i> Candidate Filtration System</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/"><i class="fas fa-home"></i> Dashboard</a>
                <a class="nav-link" href="/candidates"><i class="fas fa-users"></i> Candidates</a>
                <a class="nav-link" href="/jobs"><i class="fas fa-briefcase"></i> Jobs</a>
                <a class="nav-link" href="/stats"><i class="fas fa-chart-bar"></i> Statistics</a>
                <a class="nav-link" href="/filter"><i class="fas fa-filter"></i> Filter</a>
            </div>
        </div>
    </nav>

    <div class="hero-section">
        <div class="container text-center">
            <h1 class="display-4 mb-4"><i class="fas fa-robot"></i> AI-Powered Candidate Filtration</h1>
            <p class="lead">Streamline your recruitment process with intelligent candidate screening and evaluation</p>
            <div class="row mt-5">
                <div class="col-md-3">
                    <div class="stats-card card p-3 mb-3">
                        <h3 id="totalCandidates">4</h3>
                        <small>Total Candidates</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card card p-3 mb-3">
                        <h3 id="passedCandidates">2</h3>
                        <small>Qualified</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card card p-3 mb-3">
                        <h3 id="activeJobs">1</h3>
                        <small>Active Jobs</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card card p-3 mb-3">
                        <h3 id="successRate">66.7%</h3>
                        <small>Success Rate</small>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="container my-5">
        <div class="row">
            <div class="col-md-6 mb-4">
                <div class="card feature-card">
                    <div class="card-body text-center p-4">
                        <i class="fas fa-users fa-3x text-primary mb-3"></i>
                        <h4>Candidate Management</h4>
                        <p>View, manage, and evaluate candidate profiles with detailed information and AI-powered scoring.</p>
                        <a href="/candidates" class="btn btn-primary">View Candidates</a>
                    </div>
                </div>
            </div>
            <div class="col-md-6 mb-4">
                <div class="card feature-card">
                    <div class="card-body text-center p-4">
                        <i class="fas fa-briefcase fa-3x text-success mb-3"></i>
                        <h4>Job Criteria</h4>
                        <p>Configure job requirements and automatically match candidates based on experience, skills, and education.</p>
                        <a href="/jobs" class="btn btn-success">Manage Jobs</a>
                    </div>
                </div>
            </div>
            <div class="col-md-6 mb-4">
                <div class="card feature-card">
                    <div class="card-body text-center p-4">
                        <i class="fas fa-chart-line fa-3x text-info mb-3"></i>
                        <h4>Analytics & Reports</h4>
                        <p>Get insights into recruitment performance, success rates, and candidate demographics.</p>
                        <a href="/stats" class="btn btn-info">View Statistics</a>
                    </div>
                </div>
            </div>
            <div class="col-md-6 mb-4">
                <div class="card feature-card">
                    <div class="card-body text-center p-4">
                        <i class="fas fa-filter fa-3x text-warning mb-3"></i>
                        <h4>Smart Filtering</h4>
                        <p>Use AI-powered algorithms to automatically filter and rank candidates based on job requirements.</p>
                        <a href="/filter" class="btn btn-warning">Filter Candidates</a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer class="bg-dark text-white py-4 mt-5">
        <div class="container text-center">
            <p>&copy; 2024 Candidate Filtration System - AI-Powered Recruitment Platform</p>
            <p><small>Deployed on Vercel Serverless Platform</small></p>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Load real-time statistics
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('totalCandidates').textContent = data.statistics.candidates.total;
                    document.getElementById('passedCandidates').textContent = data.statistics.candidates.passed;
                    document.getElementById('activeJobs').textContent = data.statistics.jobs.open;
                    document.getElementById('successRate').textContent = data.statistics.candidates.success_rate_percentage + '%';
                }
            })
            .catch(err => console.log('Stats loading error:', err));
    </script>
</body>
</html>
"""

    def get_candidates_html(self):
        """Candidates listing HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Candidates - Filtration System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/"><i class="fas fa-users-cog"></i> Candidate Filtration System</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/"><i class="fas fa-home"></i> Dashboard</a>
                <a class="nav-link active" href="/candidates"><i class="fas fa-users"></i> Candidates</a>
                <a class="nav-link" href="/jobs"><i class="fas fa-briefcase"></i> Jobs</a>
                <a class="nav-link" href="/stats"><i class="fas fa-chart-bar"></i> Statistics</a>
                <a class="nav-link" href="/filter"><i class="fas fa-filter"></i> Filter</a>
            </div>
        </div>
    </nav>

    <div class="container my-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2><i class="fas fa-users text-primary"></i> Candidate Management</h2>
            <div>
                <select class="form-select" id="statusFilter" onchange="filterCandidates()">
                    <option value="">All Status</option>
                    <option value="passed">Passed</option>
                    <option value="failed">Failed</option>
                    <option value="pending">Pending</option>
                </select>
            </div>
        </div>

        <div id="candidatesContainer" class="row">
            <!-- Candidates will be loaded here -->
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function getStatusBadge(status) {
            const badges = {
                'passed': 'bg-success',
                'failed': 'bg-danger', 
                'pending': 'bg-warning text-dark'
            };
            return badges[status] || 'bg-secondary';
        }

        function loadCandidates(status = '') {
            const url = status ? `/api/candidates?status=${status}` : '/api/candidates';
            fetch(url)
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('candidatesContainer');
                    if (data.success && data.candidates.length > 0) {
                        container.innerHTML = data.candidates.map(candidate => `
                            <div class="col-md-6 mb-4">
                                <div class="card h-100">
                                    <div class="card-header d-flex justify-content-between align-items-center">
                                        <h5 class="mb-0">${candidate.name}</h5>
                                        <span class="badge ${getStatusBadge(candidate.status)}">${candidate.status.toUpperCase()}</span>
                                    </div>
                                    <div class="card-body">
                                        <p><strong><i class="fas fa-envelope"></i> Email:</strong> ${candidate.email}</p>
                                        <p><strong><i class="fas fa-phone"></i> Phone:</strong> ${candidate.phone}</p>
                                        <p><strong><i class="fas fa-clock"></i> Experience:</strong> ${candidate.experience_years} years</p>
                                        <p><strong><i class="fas fa-graduation-cap"></i> Education:</strong> ${candidate.education_certification}</p>
                                        <p><strong><i class="fas fa-tools"></i> Skills:</strong></p>
                                        <div class="mb-2">
                                            ${candidate.skills.map(skill => `<span class="badge bg-info me-1">${skill}</span>`).join('')}
                                        </div>
                                        ${candidate.score ? `<p><strong><i class="fas fa-star"></i> AI Score:</strong> <span class="badge bg-primary">${candidate.score}/100</span></p>` : ''}
                                    </div>
                                    <div class="card-footer">
                                        <small class="text-muted">Applied: ${new Date(candidate.submission_date).toLocaleDateString()}</small>
                                    </div>
                                </div>
                            </div>
                        `).join('');
                    } else {
                        container.innerHTML = '<div class="col-12 text-center"><p>No candidates found.</p></div>';
                    }
                })
                .catch(err => {
                    console.log('Error:', err);
                    document.getElementById('candidatesContainer').innerHTML = '<div class="col-12 text-center"><p>Error loading candidates.</p></div>';
                });
        }

        function filterCandidates() {
            const status = document.getElementById('statusFilter').value;
            loadCandidates(status);
        }

        // Load candidates on page load
        loadCandidates();
    </script>
</body>
</html>
"""
    
    def get_jobs_html(self):
        """Jobs listing HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jobs - Filtration System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/"><i class="fas fa-users-cog"></i> Candidate Filtration System</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/"><i class="fas fa-home"></i> Dashboard</a>
                <a class="nav-link" href="/candidates"><i class="fas fa-users"></i> Candidates</a>
                <a class="nav-link active" href="/jobs"><i class="fas fa-briefcase"></i> Jobs</a>
                <a class="nav-link" href="/stats"><i class="fas fa-chart-bar"></i> Statistics</a>
                <a class="nav-link" href="/filter"><i class="fas fa-filter"></i> Filter</a>
            </div>
        </div>
    </nav>

    <div class="container my-4">
        <h2 class="mb-4"><i class="fas fa-briefcase text-primary"></i> Job Management</h2>
        
        <div id="jobsContainer" class="row">
            <!-- Jobs will be loaded here -->
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function loadJobs() {
            fetch('/api/jobs')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('jobsContainer');
                    if (data.success && data.jobs.length > 0) {
                        container.innerHTML = data.jobs.map(job => `
                            <div class="col-md-6 mb-4">
                                <div class="card h-100">
                                    <div class="card-header d-flex justify-content-between align-items-center">
                                        <h5 class="mb-0">${job.position_title}</h5>
                                        <span class="badge ${job.job_status === 'open' ? 'bg-success' : 'bg-secondary'}">
                                            ${job.job_status.toUpperCase()}
                                        </span>
                                    </div>
                                    <div class="card-body">
                                        <p><strong><i class="fas fa-id-badge"></i> Job ID:</strong> ${job.job_id}</p>
                                        <p><strong><i class="fas fa-clock"></i> Min Experience:</strong> ${job.min_experience} years</p>
                                        <p><strong><i class="fas fa-graduation-cap"></i> Education:</strong> ${job.preferred_education}</p>
                                        <p><strong><i class="fas fa-tools"></i> Required Skills:</strong></p>
                                        <div class="mb-3">
                                            ${job.required_skills.map(skill => `<span class="badge bg-primary me-1">${skill}</span>`).join('')}
                                        </div>
                                        <div class="row text-center">
                                            <div class="col-3">
                                                <strong>${job.total_applications}</strong><br>
                                                <small class="text-muted">Total</small>
                                            </div>
                                            <div class="col-3">
                                                <strong class="text-success">${job.passed_count}</strong><br>
                                                <small class="text-muted">Passed</small>
                                            </div>
                                            <div class="col-3">
                                                <strong class="text-danger">${job.failed_count}</strong><br>
                                                <small class="text-muted">Failed</small>
                                            </div>
                                            <div class="col-3">
                                                <strong class="text-warning">${job.pending_count}</strong><br>
                                                <small class="text-muted">Pending</small>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="card-footer">
                                        <small class="text-muted">Created: ${new Date(job.created_date).toLocaleDateString()}</small>
                                    </div>
                                </div>
                            </div>
                        `).join('');
                    } else {
                        container.innerHTML = '<div class="col-12 text-center"><p>No jobs found.</p></div>';
                    }
                })
                .catch(err => {
                    console.log('Error:', err);
                    document.getElementById('jobsContainer').innerHTML = '<div class="col-12 text-center"><p>Error loading jobs.</p></div>';
                });
        }

        // Load jobs on page load
        loadJobs();
    </script>
</body>
</html>
"""

    def get_stats_html(self):
        """Statistics page HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Statistics - Filtration System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/"><i class="fas fa-users-cog"></i> Candidate Filtration System</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/"><i class="fas fa-home"></i> Dashboard</a>
                <a class="nav-link" href="/candidates"><i class="fas fa-users"></i> Candidates</a>
                <a class="nav-link" href="/jobs"><i class="fas fa-briefcase"></i> Jobs</a>
                <a class="nav-link active" href="/stats"><i class="fas fa-chart-bar"></i> Statistics</a>
                <a class="nav-link" href="/filter"><i class="fas fa-filter"></i> Filter</a>
            </div>
        </div>
    </nav>

    <div class="container my-4">
        <h2 class="mb-4"><i class="fas fa-chart-line text-primary"></i> Analytics Dashboard</h2>
        
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card bg-primary text-white">
                    <div class="card-body text-center">
                        <h3 id="totalCandidates">-</h3>
                        <p>Total Candidates</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-success text-white">
                    <div class="card-body text-center">
                        <h3 id="passedCandidates">-</h3>
                        <p>Passed</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-danger text-white">
                    <div class="card-body text-center">
                        <h3 id="failedCandidates">-</h3>
                        <p>Failed</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-warning text-dark">
                    <div class="card-body text-center">
                        <h3 id="successRate">-</h3>
                        <p>Success Rate</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Candidate Status Distribution</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="statusChart" width="400" height="200"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5>Experience Distribution</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="experienceChart" width="400" height="200"></canvas>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function loadStatistics() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        const stats = data.statistics;
                        
                        // Update summary cards
                        document.getElementById('totalCandidates').textContent = stats.candidates.total;
                        document.getElementById('passedCandidates').textContent = stats.candidates.passed;
                        document.getElementById('failedCandidates').textContent = stats.candidates.failed;
                        document.getElementById('successRate').textContent = stats.candidates.success_rate_percentage + '%';
                        
                        // Create status chart
                        const statusCtx = document.getElementById('statusChart').getContext('2d');
                        new Chart(statusCtx, {
                            type: 'doughnut',
                            data: {
                                labels: ['Passed', 'Failed', 'Pending'],
                                datasets: [{
                                    data: [stats.candidates.passed, stats.candidates.failed, stats.candidates.pending],
                                    backgroundColor: ['#28a745', '#dc3545', '#ffc107']
                                }]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false
                            }
                        });
                        
                        // Create experience chart
                        const expCtx = document.getElementById('experienceChart').getContext('2d');
                        new Chart(expCtx, {
                            type: 'bar',
                            data: {
                                labels: Object.keys(stats.demographics.experience_distribution),
                                datasets: [{
                                    label: 'Candidates',
                                    data: Object.values(stats.demographics.experience_distribution),
                                    backgroundColor: '#007bff'
                                }]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                scales: {
                                    y: {
                                        beginAtZero: true
                                    }
                                }
                            }
                        });
                    }
                })
                .catch(err => console.log('Error loading statistics:', err));
        }

        // Load statistics on page load
        loadStatistics();
    </script>
</body>
</html>
"""

    def get_filter_html(self):
        """Filter page HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Filter - Filtration System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/"><i class="fas fa-users-cog"></i> Candidate Filtration System</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="/"><i class="fas fa-home"></i> Dashboard</a>
                <a class="nav-link" href="/candidates"><i class="fas fa-users"></i> Candidates</a>
                <a class="nav-link" href="/jobs"><i class="fas fa-briefcase"></i> Jobs</a>
                <a class="nav-link" href="/stats"><i class="fas fa-chart-bar"></i> Statistics</a>
                <a class="nav-link active" href="/filter"><i class="fas fa-filter"></i> Filter</a>
            </div>
        </div>
    </nav>

    <div class="container my-4">
        <h2 class="mb-4"><i class="fas fa-filter text-primary"></i> AI Candidate Filtering</h2>
        
        <div class="card mb-4">
            <div class="card-header">
                <h5>Filter Configuration</h5>
            </div>
            <div class="card-body">
                <form id="filterForm" onsubmit="filterCandidates(event)">
                    <div class="row">
                        <div class="col-md-6">
                            <label class="form-label">Job Position</label>
                            <select class="form-select" id="jobId" required>
                                <option value="1001">Senior Software Engineer (1001)</option>
                                <option value="1002">Frontend Developer (1002)</option>
                            </select>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Minimum AI Score</label>
                            <select class="form-select" id="minScore">
                                <option value="50">50 - Basic Qualification</option>
                                <option value="60">60 - Good Match</option>
                                <option value="70" selected>70 - Strong Match</option>
                                <option value="80">80 - Excellent Match</option>
                                <option value="90">90 - Perfect Match</option>
                            </select>
                        </div>
                    </div>
                    <div class="mt-3">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-search"></i> Filter Candidates
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <div id="resultsContainer">
            <!-- Filter results will appear here -->
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function filterCandidates(event) {
            event.preventDefault();
            
            const jobId = document.getElementById('jobId').value;
            const minScore = document.getElementById('minScore').value;
            
            const resultsContainer = document.getElementById('resultsContainer');
            resultsContainer.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"></div><p>Filtering candidates...</p></div>';
            
            fetch(`/api/filter?job_id=${jobId}&min_score=${minScore}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        resultsContainer.innerHTML = `
                            <div class="card">
                                <div class="card-header d-flex justify-content-between align-items-center">
                                    <h5>Filter Results: ${data.job_criteria.position_title}</h5>
                                    <span class="badge bg-info">
                                        ${data.results.qualified_candidates} of ${data.results.total_evaluated} qualified (${data.results.success_rate})
                                    </span>
                                </div>
                                <div class="card-body">
                                    <div class="row mb-3">
                                        <div class="col-md-4">
                                            <strong>Min Experience:</strong> ${data.job_criteria.requirements.min_experience} years
                                        </div>
                                        <div class="col-md-4">
                                            <strong>Required Skills:</strong> ${data.job_criteria.requirements.required_skills.join(', ')}
                                        </div>
                                        <div class="col-md-4">
                                            <strong>Education:</strong> ${data.job_criteria.requirements.education}
                                        </div>
                                    </div>
                                    <hr>
                                    ${data.candidates.length > 0 ? 
                                        data.candidates.map(candidate => `
                                            <div class="card mb-3">
                                                <div class="card-body">
                                                    <div class="d-flex justify-content-between align-items-start">
                                                        <div>
                                                            <h6>${candidate.name}</h6>
                                                            <p class="mb-1"><strong>Experience:</strong> ${candidate.experience_years} years</p>
                                                            <p class="mb-1"><strong>Education:</strong> ${candidate.education_certification}</p>
                                                            <p class="mb-1"><strong>Skills:</strong> ${candidate.skills.join(', ')}</p>
                                                        </div>
                                                        <div class="text-end">
                                                            <span class="badge bg-success fs-6">
                                                                AI Score: ${candidate.calculated_score}/100
                                                            </span>
                                                            <br>
                                                            <small class="text-success">✓ Qualified</small>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        `).join('') 
                                        : '<div class="text-center text-muted"><p>No candidates meet the filtering criteria.</p></div>'
                                    }
                                </div>
                            </div>
                        `;
                    } else {
                        resultsContainer.innerHTML = `<div class="alert alert-danger">Error: ${data.error}</div>`;
                    }
                })
                .catch(err => {
                    console.log('Error:', err);
                    resultsContainer.innerHTML = '<div class="alert alert-danger">Error filtering candidates</div>';
                });
        }
    </script>
</body>
</html>
"""

    def get_404_html(self):
        """404 page HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page Not Found - Filtration System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <div class="container text-center mt-5">
        <i class="fas fa-exclamation-triangle fa-5x text-warning mb-4"></i>
        <h1>Page Not Found</h1>
        <p class="lead">The page you're looking for doesn't exist.</p>
        <a href="/" class="btn btn-primary">Return to Dashboard</a>
    </div>
</body>
</html>
"""

    # API endpoint methods (same as before)
    def health_endpoint(self):
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "service": "candidate-filtration-system",
            "platform": "Vercel Serverless",
            "version": "1.0.0",
            "database_status": "demo_mode",
            "features_active": ["filtering", "scoring", "analytics", "web_ui"]
        }
    
    def version_endpoint(self):
        return {
            "version": "1.0.0",
            "name": "Candidate Filtration System",
            "description": "AI-powered recruitment and candidate screening platform with web interface",
            "platform": "Vercel Serverless",
            "features": {
                "web_interface": "Complete HTML frontend with interactive UI",
                "candidate_management": "Store and manage candidate profiles",
                "automated_filtering": "AI-powered candidate screening",
                "multi_criteria_evaluation": "Experience, skills, education assessment",
                "statistical_reporting": "Analytics and insights with charts"
            },
            "pages": ["dashboard", "candidates", "jobs", "statistics", "filter"],
            "api_endpoints": 6,
            "demo_mode": True
        }
    
    def candidates_endpoint(self, query_params):
        candidates = self.sample_candidates.copy()
        
        # Filter by status
        status_filter = query_params.get('status', [None])[0]
        if status_filter:
            candidates = [c for c in candidates if c.get('status') == status_filter]
        
        # Filter by job_id (simplified)
        job_id = query_params.get('job_id', [None])[0]
        if job_id:
            candidates = candidates[:2]  # Demo: show first 2 candidates
        
        # Add filtering summary
        for candidate in candidates:
            candidate['filtration_summary'] = self.get_candidate_summary(candidate)
        
        return {
            "success": True,
            "count": len(candidates),
            "candidates": candidates,
            "filters_applied": {
                "status": status_filter,
                "job_id": job_id
            },
            "available_statuses": ["pending", "passed", "failed"],
            "note": "Demo candidate data with AI filtration results"
        }
    
    def jobs_endpoint(self, query_params):
        jobs = self.job_criteria.copy()
        
        # Filter by status
        status_filter = query_params.get('status', [None])[0]
        if status_filter:
            jobs = [j for j in jobs if j.get('job_status') == status_filter]
        
        return {
            "success": True,
            "count": len(jobs),
            "jobs": jobs,
            "filters_applied": {
                "status": status_filter
            },
            "available_statuses": ["open", "closed"],
            "note": "Demo job criteria with candidate statistics"
        }
    
    def stats_endpoint(self):
        candidates = self.sample_candidates
        jobs = self.job_criteria
        
        # Calculate statistics
        total_candidates = len(candidates)
        passed_candidates = len([c for c in candidates if c.get('status') == 'passed'])
        failed_candidates = len([c for c in candidates if c.get('status') == 'failed'])
        pending_candidates = len([c for c in candidates if c.get('status') == 'pending'])
        
        # Calculate success rate
        evaluated_candidates = passed_candidates + failed_candidates
        success_rate = (passed_candidates / evaluated_candidates * 100) if evaluated_candidates > 0 else 0
        
        # Education distribution
        education_stats = {}
        for candidate in candidates:
            edu = candidate.get('education', 'unknown')
            education_stats[edu] = education_stats.get(edu, 0) + 1
        
        # Experience distribution
        experience_ranges = {'0-2 years': 0, '3-5 years': 0, '6+ years': 0}
        for candidate in candidates:
            exp = candidate.get('experience_years', 0)
            if exp <= 2:
                experience_ranges['0-2 years'] += 1
            elif exp <= 5:
                experience_ranges['3-5 years'] += 1
            else:
                experience_ranges['6+ years'] += 1
        
        return {
            "success": True,
            "statistics": {
                "candidates": {
                    "total": total_candidates,
                    "passed": passed_candidates,
                    "failed": failed_candidates,
                    "pending": pending_candidates,
                    "success_rate_percentage": round(success_rate, 1)
                },
                "jobs": {
                    "total": len(jobs),
                    "open": len([j for j in jobs if j.get('job_status') == 'open']),
                    "closed": len([j for j in jobs if j.get('job_status') == 'closed'])
                },
                "demographics": {
                    "education_distribution": education_stats,
                    "experience_distribution": experience_ranges
                },
                "performance": {
                    "average_score": round(sum(c.get('score', 0) for c in candidates if c.get('score')) / len([c for c in candidates if c.get('score')]), 1),
                    "top_skills": ["Python", "JavaScript", "SQL", "Java", "React"]
                }
            },
            "timestamp": datetime.now().isoformat(),
            "note": "Demo statistics from sample candidate data"
        }
    
    def filter_endpoint(self, query_params):
        # Simulate candidate filtering based on job criteria
        job_id = query_params.get('job_id', ['1001'])[0]
        min_score = int(query_params.get('min_score', ['70'])[0])
        
        # Find job criteria
        job = next((j for j in self.job_criteria if str(j['job_id']) == str(job_id)), None)
        if not job:
            return {"error": "Job not found", "available_jobs": [str(j['job_id']) for j in self.job_criteria]}
        
        # Filter candidates based on criteria
        filtered_candidates = []
        for candidate in self.sample_candidates:
            score = self.calculate_candidate_score(candidate, job)
            if score >= min_score:
                candidate_copy = candidate.copy()
                candidate_copy['calculated_score'] = score
                candidate_copy['meets_criteria'] = True
                filtered_candidates.append(candidate_copy)
        
        return {
            "success": True,
            "job_criteria": {
                "job_id": job['job_id'],
                "position_title": job['position_title'],
                "requirements": {
                    "min_experience": job['min_experience'],
                    "required_skills": job['required_skills'],
                    "education": job['preferred_education']
                }
            },
            "filter_params": {
                "min_score": min_score,
                "job_id": job_id
            },
            "results": {
                "total_evaluated": len(self.sample_candidates),
                "qualified_candidates": len(filtered_candidates),
                "success_rate": f"{len(filtered_candidates) / len(self.sample_candidates) * 100:.1f}%"
            },
            "candidates": filtered_candidates,
            "note": "Automated AI-powered candidate filtration results"
        }
    
    def calculate_candidate_score(self, candidate, job):
        """Calculate candidate score based on job criteria"""
        score = 0
        
        # Experience scoring (40% weight)
        exp_score = min(candidate.get('experience_years', 0) / job['min_experience'] * 40, 40)
        score += exp_score
        
        # Skills scoring (40% weight)
        candidate_skills = set(skill.lower() for skill in candidate.get('skills', []))
        required_skills = set(skill.lower() for skill in job['required_skills'])
        skill_match = len(candidate_skills.intersection(required_skills)) / len(required_skills)
        skill_score = skill_match * 40
        score += skill_score
        
        # Education scoring (20% weight)
        education_levels = {'high_school': 1, 'associate': 2, 'bachelor': 3, 'master': 4, 'phd': 5}
        candidate_edu = education_levels.get(candidate.get('education'), 1)
        required_edu = education_levels.get(job['preferred_education'], 1)
        edu_score = min(candidate_edu / required_edu * 20, 20)
        score += edu_score
        
        return round(score, 1)
    
    def get_candidate_summary(self, candidate):
        """Get filtration summary for a candidate"""
        return {
            "total_experience": f"{candidate.get('experience_years', 0)} years",
            "position_experience": f"{candidate.get('position_experience_years', 0)} years",
            "skill_count": len(candidate.get('skills', [])),
            "education_level": candidate.get('education', 'unknown').title(),
            "status": candidate.get('status', 'unknown'),
            "score": candidate.get('score', 'not_calculated')
        }
    
    def not_found_endpoint(self):
        return {
            "error": "API endpoint not found",
            "available_endpoints": [
                "/api/health", 
                "/api/version",
                "/api/candidates",
                "/api/jobs",
                "/api/stats",
                "/api/filter"
            ],
            "web_pages": [
                "/", "/candidates", "/jobs", "/stats", "/filter"
            ],
            "suggestion": "Check the API documentation for valid endpoints"
        }
    
    def send_error_response(self, error_message):
        self.send_response(500)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        error_response = {
            "error": "Internal server error",
            "message": error_message,
            "status_code": 500
        }
        
        self.wfile.write(json.dumps(error_response, indent=2).encode())

    def do_POST(self):
        # Handle POST requests (for form submissions in the future)
        self.do_GET()
        
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()