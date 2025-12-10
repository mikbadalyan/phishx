# PhishGuard - Advanced Phishing Email Detection Platform

A modern, feature-rich web-based platform that detects phishing emails using Machine Learning and Cybersecurity techniques with user authentication, admin panel, and comprehensive analytics.

## Project Structure

```
phishing_platform/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── setup.sh            # Setup script
├── run.sh              # Run script
├── create_admin.py     # Script to create admin user
├── README.md           # This file
├── templates/
│   ├── index.html      # Landing page
│   ├── login.html      # User login page
│   ├── register.html   # User registration page
│   ├── dashboard.html  # User dashboard
│   ├── admin.html      # Admin panel
│   ├── profile.html    # User profile settings
│   ├── reports.html    # Analysis reports
│   ├── analysis_detail.html # Detailed analysis view
│   ├── training.html   # Cybersecurity training
│   ├── settings.html   # System settings
│   └── email_analysis.html # Email analysis interface
├── static/
│   ├── style.css               # Modern styling for the web interface
│   └── phishing-illustration.png # Illustration for homepage
├── modules/
│   ├── ml_model.py     # ML/NLP model for phishing detection (Mikayel)
│   └── cyber_analysis.py # Cybersecurity analysis (Karen & Vahe)
└── sample_phishing_email.txt # Sample email for testing
```

## Features

### User Authentication & Management
- Secure user registration and login system
- Password hashing with pbkdf2:sha256
- Session management with Flask-Login
- Role-based access control (User/Admin)
- Profile management with personal information
- Password update functionality

### Modern Dashboard
- Interactive file upload with drag & drop
- Real-time phishing detection with risk scoring
- Visual risk indicators and progress meters
- Recent analyses history
- Responsive design for all devices

### Email Analysis
- Dedicated email analysis interface
- File upload with drag & drop support
- Detailed risk assessment with visual indicators
- Analysis history with filtering and sorting
- Individual analysis detail views

### Advanced Analytics & Reporting
- Comprehensive analysis reports
- Risk trend visualization
- Detailed feature breakdown
- Classification distribution charts
- PDF report generation for individual analyses
- CSV export for all analyses

### Training & Education
- Interactive cybersecurity training modules
- Phishing recognition training
- Password security best practices
- Social engineering defense
- Simulated phishing exercises

### System Settings
- General settings (language, timezone, theme)
- Notification preferences
- Security settings with 2FA
- Session management
- Data export functionality

### Admin Panel
- User management (view, edit, delete)
- System-wide email analyses overview
- Platform statistics and metrics
- Activity monitoring
- Access restricted to admin users

### Phishing Detection Engine
- Machine Learning-based email classification
- Advanced NLP feature extraction
- Risk scoring with detailed component analysis
- Multi-factor phishing detection
- Real-time threat assessment

## Technology Stack

- **Backend:** Python Flask
- **Database:** SQLite with SQLAlchemy ORM
- **Authentication:** Flask-Login
- **Frontend:** HTML, CSS, JavaScript with modern UI components
- **ML/NLP:** Custom Python modules with advanced feature extraction
- **Cybersecurity:** Custom Python modules
- **Reporting:** ReportLab for PDF generation
- **Styling:** Modern CSS with responsive design

## Setup Instructions

### Automated Setup (Recommended)

1. **Run the setup script:**
   ```bash
   ./setup.sh
   ```

### Manual Setup

1. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Create the uploads directory:**
   ```bash
   mkdir uploads
   ```

4. **Create the admin user:**
   ```bash
   python create_admin.py
   ```

## Running the Application

### Using the Run Script (Recommended)

```bash
./run.sh
```

### Manual Run

1. **Activate the virtual environment:**
   ```bash
   source venv/bin/activate
   ```

2. **Set environment variables:**
   ```bash
   export FLASK_APP=app.py
   export FLASK_ENV=development
   ```

3. **Run the Flask application:**
   ```bash
   flask run
   ```

4. **Access the application:**
   Open your browser and go to http://127.0.0.1:5000/

## Default Accounts

### Admin Account
- Username: admin
- Password: admin123

## Testing the Application

1. Navigate to http://127.0.0.1:5000/
2. Click "Login" and use the admin credentials
3. Upload the provided [sample_phishing_email.txt](file:///Users/mikbadalyan/Desktop/phishing_platform/sample_phishing_email.txt) file
4. View the analysis results in the dashboard
5. Explore all sections: Email Analysis, Reports, Training, Profile, Settings
6. Check the admin panel to see all users and analyses
7. Test PDF report generation and CSV export features

## Team Members

- **Mikayel Badalyan** - ML/NLP model, risk scoring, data visualization
- **Albert** - Data visualization, ML model evaluation
- **Karen** - Email header analysis, SPF/DKIM/DMARC checks
- **Vahe** - Link analysis, phishing pattern recognition

## Future Enhancements

- Integration with email clients (Outlook, Gmail)
- Advanced charting with Chart.js or D3.js
- Real-time notifications
- Mobile application
- API for third-party integrations
- Multi-language support
- Advanced threat intelligence feeds
- Automated email scanning integration