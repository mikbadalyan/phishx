from app import app, db, User
from werkzeug.security import generate_password_hash

def create_admin_user():
    with app.app_context():
        # Check if admin user already exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            # Create admin user
            admin = User()
            admin.username = 'admin'
            admin.email = 'admin@phishingplatform.com'
            admin.is_admin = True
            admin.password_hash = generate_password_hash('admin123', method='pbkdf2:sha256')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
            print("Username: admin")
            print("Password: admin123")
        else:
            print("Admin user already exists!")

if __name__ == '__main__':
    create_admin_user()