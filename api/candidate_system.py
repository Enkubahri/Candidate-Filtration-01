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
            
            # Set response headers
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            self.send_header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
            self.end_headers()
            
            # Route handling
            if path == '' or path == '/':
                response = self.home_endpoint()
            elif path == '/health' or path == '/api/health':
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
            
            # Send JSON response
            self.wfile.write(json.dumps(response, indent=2, default=str).encode())
            
        except Exception as e:
            self.send_error_response(str(e))
    
    def do_POST(self):
        # Handle POST requests (for form submissions in the future)
        self.do_GET()
        
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
    
    def home_endpoint(self):
        return {
            "message": "Candidate Filtration System API",
            "status": "online",
            "version": "1.0.0",
            "platform": "Vercel Serverless",
            "description": "AI-powered candidate screening and filtration system",
            "features": [
                "Candidate management and scoring",
                "Job criteria configuration", 
                "Automated candidate filtering",
                "Statistical reporting",
                "Multi-criteria evaluation"
            ],
            "endpoints": {
                "health": "/health - Health check",
                "version": "/api/version - API information",
                "candidates": "/api/candidates - Get all candidates (filter by status, job_id)",
                "jobs": "/api/jobs - Get job postings and criteria",
                "stats": "/api/stats - System statistics and analytics",
                "filter": "/api/filter - Filter candidates by criteria"
            },
            "demo_note": "This is a demo deployment with sample data for testing purposes"
        }
    
    def health_endpoint(self):
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "service": "candidate-filtration-system",
            "platform": "Vercel Serverless",
            "version": "1.0.0",
            "database_status": "demo_mode",
            "features_active": ["filtering", "scoring", "analytics"]
        }
    
    def version_endpoint(self):
        return {
            "version": "1.0.0",
            "name": "Candidate Filtration System",
            "description": "AI-powered recruitment and candidate screening platform",
            "platform": "Vercel Serverless",
            "author": "Developed for efficient candidate evaluation",
            "features": {
                "candidate_management": "Store and manage candidate profiles",
                "automated_filtering": "AI-powered candidate screening",
                "multi_criteria_evaluation": "Experience, skills, education assessment",
                "statistical_reporting": "Analytics and insights",
                "job_matching": "Match candidates to job requirements"
            },
            "api_endpoints": 6,
            "demo_mode": True,
            "limitations": [
                "Demo data only (no persistent storage)",
                "No file uploads in serverless mode",
                "Simplified filtering algorithms"
            ]
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
            # In a real system, this would filter by actual job applications
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
            "error": "Endpoint not found",
            "available_endpoints": [
                "/",
                "/health", 
                "/api/version",
                "/api/candidates",
                "/api/jobs",
                "/api/stats",
                "/api/filter"
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