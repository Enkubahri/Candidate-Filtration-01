# Candidate Filtration System API

This is the deployment-ready API version of the Candidate Filtration System.

## Quick Start

### Local Development

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set Environment Variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Run the API**
   ```bash
   python index.py
   ```

The API will be available at `http://localhost:5000`

### Production Deployment

#### Using Gunicorn (Recommended)
```bash
gunicorn index:app --bind 0.0.0.0:5000 --workers 2
```

#### Using Docker
```bash
# Build the container
docker build -t candidate-filtration-api .

# Run the container
docker run -p 5000:5000 candidate-filtration-api
```

## API Endpoints

### Health Check
- `GET /health` or `GET /api/health`
  - Returns system health status
  - Used for monitoring and load balancer health checks

### Version Information
- `GET /api/version`
  - Returns API version and available endpoints

### Candidates
- `GET /api/candidates`
  - Get all candidates
  - Query parameters:
    - `status`: Filter by status (pending, passed, failed)
    - `job_id`: Filter by job ID

### Jobs
- `GET /api/jobs`
  - Get all job criteria/positions
  - Query parameters:
    - `status`: Filter by job status (open, closed)

### Statistics
- `GET /api/stats`
  - Get system statistics
  - Returns candidate, job, and user counts

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Environment mode | `development` |
| `SECRET_KEY` | Flask secret key | Required |
| `HOST` | Server host | `0.0.0.0` |
| `PORT` | Server port | `5000` |
| `DATABASE_URL` | Database file path | `candidates.db` |
| `UPLOAD_FOLDER` | File upload directory | `uploads` |

## Deployment Platforms

### Heroku
1. Create a new Heroku app
2. Set environment variables in Heroku dashboard
3. Deploy using Git:
   ```bash
   git add .
   git commit -m "Deploy API"
   git push heroku main
   ```

### Railway/Render
1. Connect your GitHub repository
2. Set environment variables
3. Deploy automatically

### VPS/Server
1. Install Python 3.8+
2. Clone repository
3. Install dependencies
4. Set up environment variables
5. Run with Gunicorn behind nginx

## API Response Format

### Success Response
```json
{
  "success": true,
  "data": {...},
  "count": 10,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Error Response
```json
{
  "success": false,
  "error": "Error description",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Security Notes

- Change the `SECRET_KEY` for production
- Use HTTPS in production
- Implement rate limiting if needed
- Configure CORS appropriately
- Keep dependencies updated

## Monitoring

The API includes a health check endpoint at `/health` that returns:
- System status
- Timestamp
- Version information
- Service name

Use this endpoint for:
- Load balancer health checks
- Monitoring systems
- Uptime monitoring services

## Support

For issues or questions, please check the main application documentation or create an issue in the repository.
