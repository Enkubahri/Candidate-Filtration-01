from http.server import BaseHTTPRequestHandler
import json
from urllib.parse import urlparse, parse_qs

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Parse the URL
        url_parts = urlparse(self.path)
        path = url_parts.path
        query_params = parse_qs(url_parts.query)
        
        # Set response headers
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        # Route handling
        if path == '/' or path == '':
            response = {
                "message": "Hello Vercel!",
                "status": "working",
                "platform": "vercel-serverless",
                "endpoints": ["/health", "/api/version", "/api/candidates"]
            }
        elif path == '/health' or path == '/api/health':
            response = {
                "status": "healthy",
                "platform": "vercel",
                "service": "candidate-filtration-system"
            }
        elif path == '/api/version':
            response = {
                "version": "1.0.0",
                "name": "Candidate Filtration System",
                "platform": "Vercel Serverless"
            }
        elif path == '/api/candidates':
            response = {
                "success": True,
                "count": 2,
                "candidates": [
                    {"id": 1, "name": "John Doe", "status": "pending"},
                    {"id": 2, "name": "Jane Smith", "status": "passed"}
                ],
                "note": "Demo data for Vercel deployment"
            }
        else:
            response = {
                "error": "Not found",
                "available_endpoints": ["/", "/health", "/api/version", "/api/candidates"]
            }
        
        # Send JSON response
        self.wfile.write(json.dumps(response, indent=2).encode())
        
    def do_POST(self):
        self.do_GET()  # Handle POST same as GET for now
        
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()