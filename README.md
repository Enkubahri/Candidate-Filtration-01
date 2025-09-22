# Candidate Filtration System

An automated recruitment system that filters job candidates based on admin-defined criteria and sends qualified candidate information via email.

## Features

- **Candidate Application Form**: Allows candidates to submit their information and upload resumes
- **Admin Criteria Management**: Interface for setting filtration criteria (experience, skills, education)
- **Automated Filtering**: Compares candidate qualifications against criteria automatically
- **Email Notifications**: Sends qualified candidate details to specified email addresses
- **Resume Upload**: Supports PDF and Word document uploads
- **Application Tracking**: View all applications with pass/fail status

## How It Works

1. **Admin Setup**: Administrator sets filtration criteria including:
   - Minimum years of experience
   - Required skills (comma-separated)
   - Minimum education level
   - Notification email address

2. **Candidate Application**: Candidates fill out the application form with:
   - Personal information (name, email, phone)
   - Years of experience
   - Education level
   - Skills (comma-separated)
   - Resume upload (PDF/Word)

3. **Automatic Evaluation**: The system evaluates candidates based on:
   - Experience requirement (exact match)
   - Skills requirement (70% match threshold)
   - Education requirement (minimum level)
   - Candidates must meet 2 out of 3 criteria to pass

4. **Email Notification**: Qualified candidates' information is automatically emailed to the admin with resume attached

## Setup Instructions

### Prerequisites

You'll need Python installed on your system. To check if you have Python:

```bash
python --version
```

### Installation

1. **Clone/Download the project** to your computer

2. **Install Python** if not already installed:
   - Visit https://python.org/downloads
   - Download and install the latest version
   - Make sure to check "Add Python to PATH" during installation

3. **Set up virtual environment**:
   ```bash
   cd candidate-filtration-system
   python -m venv venv
   
   # Activate virtual environment
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

5. **Configure email settings** (optional):
   - Copy `.env.example` to `.env`
   - Fill in your email credentials for sending notifications
   - Example for Gmail:
     ```
     MAIL_USERNAME=your-email@gmail.com
     MAIL_PASSWORD=your-app-password
     ```
   - Note: For Gmail, you'll need to use an "App Password" instead of your regular password

### Running the Application

1. **Start the application**:
   ```bash
   python app.py
   ```

2. **Access the system**:
   - Open your web browser
   - Go to `http://localhost:5000`

## Usage

### For Administrators

1. **Set Criteria**: 
   - Visit the Admin Panel (`/admin`)
   - Set minimum experience, required skills, education level, and notification email
   - Save the criteria

2. **View Applications**:
   - Visit "View Applications" to see all submitted applications
   - Applications are color-coded: Green (passed), Red (failed), Yellow (pending)
   - View candidate details and download resumes

### For Candidates

1. **Submit Application**:
   - Visit "Apply Now" (`/candidate`)
   - Fill out all required fields
   - Upload your resume (PDF or Word format, max 16MB)
   - Submit the application

2. **Automatic Processing**:
   - Your application will be automatically evaluated
   - If you meet the criteria, your information will be sent to the hiring team
   - You'll see a confirmation message upon submission

## File Structure

```
candidate-filtration-system/
├── app.py                 # Main Flask application
├── config.py             # Configuration settings
├── requirements.txt      # Python dependencies
├── .env.example         # Environment variables template
├── README.md            # This file
├── candidates.db        # SQLite database (created automatically)
├── templates/           # HTML templates
│   ├── base.html        # Base template
│   ├── index.html       # Homepage
│   ├── candidate_form.html # Candidate application form
│   ├── admin_form.html  # Admin criteria form
│   └── candidates_list.html # Applications view
├── static/              # Static files
│   ├── css/
│   │   └── style.css    # Custom styles
│   └── js/
│       └── main.js      # JavaScript functionality
└── uploads/             # Resume upload directory
```

## Customization

### Filtration Logic

The current filtration logic can be modified in the `check_candidate_criteria()` function in `app.py`:

- **Skill Matching**: Currently requires 70% match (configurable)
- **Pass Threshold**: Currently requires 2 out of 3 criteria (configurable)
- **Education Levels**: Hierarchical comparison (PhD > Master's > Bachelor's > Associate > High School)

### Email Templates

Customize the email notification format by modifying the `send_notification_email()` function in `app.py`.

### Form Fields

Add new fields by:
1. Adding them to the form classes in `app.py`
2. Adding corresponding database columns
3. Updating the HTML templates
4. Modifying the filtration logic if needed

## Troubleshooting

### Common Issues

1. **Python not found**: Make sure Python is installed and added to PATH
2. **Module not found**: Activate virtual environment and install requirements
3. **File upload errors**: Check file size (max 16MB) and format (PDF/Word only)
4. **Email not sending**: Verify email credentials and SMTP settings
5. **Database errors**: Make sure you have write permissions in the project directory

### Security Notes

- Change the SECRET_KEY in production
- Use environment variables for sensitive information
- Consider adding authentication for admin routes
- Implement rate limiting for form submissions
- Validate and sanitize all user inputs

## License

This project is for educational/demonstration purposes. Feel free to modify and use as needed.
