from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
import re
import io
import csv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

from modules.phishing_engine import EmailRiskAnalyzer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'phishing_platform.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File upload configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'eml', 'txt', 'msg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

analyzer = EmailRiskAnalyzer()

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    
    # Relationship with email analyses
    analyses = db.relationship('EmailAnalysis', backref='user', lazy=True, cascade="all, delete-orphan")
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class EmailAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    filepath = db.Column(db.String(300), nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    classification = db.Column(db.String(50), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Store features as a JSON string
    features = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<EmailAnalysis {self.filename}>'

# Create tables
with app.app_context():
    db.create_all()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def read_uploaded_file(filepath):
    """Read the content of an uploaded file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return ""

def classify_email(email_content, filename=None):
    """Run the phishing analyzer and return a normalized payload for persistence."""
    analysis = analyzer.analyze(email_content, filename=filename)
    classification = 'Phishing' if analysis['label'] == 'phishing' else 'Legitimate'
    
    result = {
        'filename': filename or 'inline_submission',
        'risk_score': analysis['risk_score'],
        'risk_score_normalized': analysis['risk_score_normalized'],
        'classification': classification,
        'features': analysis['display_features'],
        'indicators': analysis['indicators'],
        'meta': analysis['meta']
    }
    return result

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Validate input
        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return redirect(url_for('register'))
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        user = User()
        user.username = username
        user.email = email
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's recent analyses (last 10)
    analyses = EmailAnalysis.query.filter_by(user_id=current_user.id).order_by(EmailAnalysis.uploaded_at.desc()).limit(10).all()
    return render_template('dashboard.html', analyses=analyses)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied: Administrator privileges required', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all users and analyses
    users = User.query.all()
    analyses = EmailAnalysis.query.order_by(EmailAnalysis.uploaded_at.desc()).all()
    return render_template('admin.html', users=users, analyses=analyses)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Update profile information
        current_user.first_name = request.form.get('first_name', '')
        current_user.last_name = request.form.get('last_name', '')
        current_user.bio = request.form.get('bio', '')
        
        # Update password if provided
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        
        if current_password and new_password:
            if current_user.check_password(current_password):
                if len(new_password) >= 6:
                    current_user.set_password(new_password)
                    flash('Profile and password updated successfully!', 'success')
                else:
                    flash('New password must be at least 6 characters long', 'error')
            else:
                flash('Current password is incorrect', 'error')
        else:
            flash('Profile updated successfully!', 'success')
        
        db.session.commit()
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

@app.route('/reports')
@login_required
def reports():
    # Get all user's analyses for reporting
    analyses = EmailAnalysis.query.filter_by(user_id=current_user.id).order_by(EmailAnalysis.uploaded_at.desc()).all()
    return render_template('reports.html', analyses=analyses)

@app.route('/training')
@login_required
def training():
    return render_template('training.html')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/email_analysis')
@login_required
def email_analysis():
    # Get all user's analyses
    analyses = EmailAnalysis.query.filter_by(user_id=current_user.id).order_by(EmailAnalysis.uploaded_at.desc()).all()
    return render_template('email_analysis.html', analyses=analyses)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'emailFile' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['emailFile']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename) if file.filename else 'unnamed_file'
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Read the email content
        email_content = read_uploaded_file(filepath)
        
        # Analyze the email with the explainable engine
        analysis_result = classify_email(email_content, filename=filename)
        
        # Persist results, storing full explainability payload for later drill-down
        stored_features = {
            'display_features': analysis_result['features'],
            'indicators': analysis_result['indicators'],
            'meta': analysis_result['meta']
        }
        
        analysis = EmailAnalysis(
            filename=filename,
            filepath=filepath,
            risk_score=analysis_result['risk_score'],
            classification=analysis_result['classification'],
            user_id=current_user.id,
            features=json.dumps(stored_features)
        )
        
        db.session.add(analysis)
        db.session.commit()
        
        # Combine results for immediate UI/API consumption
        result = {
            'filename': filename,
            'risk_score': analysis_result['risk_score'],
            'risk_score_normalized': analysis_result['risk_score_normalized'],
            'classification': analysis_result['classification'],
            'features': analysis_result['features'],
            'indicators': analysis_result['indicators'],
            'meta': analysis_result['meta']
        }
        
        return jsonify(result)
    
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/api/analyze', methods=['POST'])
@login_required
def api_analyze():
    """
    API endpoint for analyzing raw email content (EML or plain text).
    Accepts JSON payload with `raw_email`/`text` or a file upload under `emailFile`.
    """
    raw_email = ''
    filename = 'inline_submission'
    persist = True
    
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        raw_email = payload.get('raw_email') or payload.get('text') or payload.get('body', '')
        filename = payload.get('filename', filename)
        persist = payload.get('persist', True)
    elif 'emailFile' in request.files:
        file = request.files['emailFile']
        filename = secure_filename(file.filename) if file.filename else filename
        raw_email = file.read().decode('utf-8', errors='ignore')
    
    if not raw_email:
        return jsonify({'error': 'No email content provided'}), 400
    
    analysis_result = classify_email(raw_email, filename=filename)
    
    # Optionally persist the analysis (default true for authenticated users)
    if persist and current_user.is_authenticated:
        stored_features = {
            'display_features': analysis_result['features'],
            'indicators': analysis_result['indicators'],
            'meta': analysis_result['meta']
        }
        analysis = EmailAnalysis(
            filename=filename or 'inline_submission',
            filepath='api_submission',
            risk_score=analysis_result['risk_score'],
            classification=analysis_result['classification'],
            user_id=current_user.id,
            features=json.dumps(stored_features)
        )
        db.session.add(analysis)
        db.session.commit()
        analysis_result['analysis_id'] = analysis.id
    
    return jsonify(analysis_result), 200

@app.route('/analysis/<int:analysis_id>')
@login_required
def view_analysis(analysis_id):
    analysis = EmailAnalysis.query.get_or_404(analysis_id)
    
    # Check if user owns this analysis or is admin
    if analysis.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied: You do not have permission to view this analysis', 'error')
        return redirect(url_for('dashboard'))
    
    # Parse features from JSON, supporting both legacy lists and new explainability payloads
    raw_features = json.loads(analysis.features) if analysis.features else {}
    indicators = []
    meta = {}
    if isinstance(raw_features, dict):
        features = raw_features.get('display_features', [])
        indicators = raw_features.get('indicators', [])
        meta = raw_features.get('meta', {})
    else:
        features = raw_features
    
    return render_template('analysis_detail.html', analysis=analysis, features=features, indicators=indicators, meta=meta)

@app.route('/delete_analysis/<int:analysis_id>', methods=['POST'])
@login_required
def delete_analysis(analysis_id):
    analysis = EmailAnalysis.query.get_or_404(analysis_id)
    
    # Check if user owns this analysis or is admin
    if analysis.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied: You do not have permission to delete this analysis', 'error')
        return redirect(url_for('dashboard'))
    
    # Delete the file from filesystem
    try:
        if os.path.exists(analysis.filepath):
            os.remove(analysis.filepath)
    except Exception as e:
        print(f"Error deleting file: {e}")
    
    # Delete from database
    db.session.delete(analysis)
    db.session.commit()
    
    flash('Analysis deleted successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/export_report/<int:analysis_id>')
@login_required
def export_report(analysis_id):
    analysis = EmailAnalysis.query.get_or_404(analysis_id)
    
    # Check if user owns this analysis or is admin
    if analysis.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    
    # Create PDF report
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title = Paragraph("Phishing Email Analysis Report", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 12))
    
    # Analysis details
    data = [
        ['Filename:', analysis.filename],
        ['Classification:', analysis.classification],
        ['Risk Score:', f"{analysis.risk_score}%"],
        ['Analysis Date:', analysis.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')],
    ]
    
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.grey),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(table)
    story.append(Spacer(1, 12))
    
    # Features table
    features = json.loads(analysis.features) if analysis.features else []
    if features:
        story.append(Paragraph("Analysis Features:", styles['Heading2']))
        feature_data = [['Feature', 'Value']]
        for feature in features:
            feature_data.append([feature['name'], str(feature['value'])])
        
        feature_table = Table(feature_data)
        feature_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(feature_table)
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    
    # Return PDF
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'phishing_analysis_{analysis.id}.pdf',
        mimetype='application/pdf'
    )

@app.route('/export_csv')
@login_required
def export_csv():
    # Get all user's analyses
    analyses = EmailAnalysis.query.filter_by(user_id=current_user.id).order_by(EmailAnalysis.uploaded_at.desc()).all()
    
    # Create CSV
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    
    # Write header
    writer.writerow(['ID', 'Filename', 'Risk Score', 'Classification', 'Upload Date'])
    
    # Write data
    for analysis in analyses:
        writer.writerow([
            analysis.id,
            analysis.filename,
            analysis.risk_score,
            analysis.classification,
            analysis.uploaded_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    # Return CSV
    buffer.seek(0)
    return send_file(
        io.BytesIO(buffer.getvalue().encode()),
        as_attachment=True,
        download_name='phishing_analyses.csv',
        mimetype='text/csv'
    )

if __name__ == '__main__':
    app.run(debug=True)
