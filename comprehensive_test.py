import requests
import time

# Test the application functionality
session = requests.Session()

print("=== PHISHGUARD PLATFORM FUNCTIONALITY TEST ===\n")

# 1. Test homepage access
try:
    response = session.get('http://127.0.0.1:5000/')
    print(f"1. Homepage access: {'✅ PASS' if response.status_code == 200 else '❌ FAIL'} (Status: {response.status_code})")
except Exception as e:
    print(f"1. Homepage access: ❌ FAIL (Error: {e})")

# 2. Test login page access
try:
    response = session.get('http://127.0.0.1:5000/login')
    print(f"2. Login page access: {'✅ PASS' if response.status_code == 200 else '❌ FAIL'} (Status: {response.status_code})")
except Exception as e:
    print(f"2. Login page access: ❌ FAIL (Error: {e})")

# 3. Test user login
try:
    login_data = {
        'username': 'admin',
        'password': 'admin123'
    }
    response = session.post('http://127.0.0.1:5000/login', data=login_data)
    login_success = response.status_code in [200, 302]
    print(f"3. User login: {'✅ PASS' if login_success else '❌ FAIL'} (Status: {response.status_code})")
except Exception as e:
    print(f"3. User login: ❌ FAIL (Error: {e})")

# 4. Test dashboard access
try:
    response = session.get('http://127.0.0.1:5000/dashboard')
    print(f"4. Dashboard access: {'✅ PASS' if response.status_code == 200 else '❌ FAIL'} (Status: {response.status_code})")
except Exception as e:
    print(f"4. Dashboard access: ❌ FAIL (Error: {e})")

# 5. Test email analysis page
try:
    response = session.get('http://127.0.0.1:5000/email_analysis')
    print(f"5. Email analysis page: {'✅ PASS' if response.status_code == 200 else '❌ FAIL'} (Status: {response.status_code})")
except Exception as e:
    print(f"5. Email analysis page: ❌ FAIL (Error: {e})")

# 6. Test reports page
try:
    response = session.get('http://127.0.0.1:5000/reports')
    print(f"6. Reports page: {'✅ PASS' if response.status_code == 200 else '❌ FAIL'} (Status: {response.status_code})")
except Exception as e:
    print(f"6. Reports page: ❌ FAIL (Error: {e})")

# 7. Test training page
try:
    response = session.get('http://127.0.0.1:5000/training')
    print(f"7. Training page: {'✅ PASS' if response.status_code == 200 else '❌ FAIL'} (Status: {response.status_code})")
except Exception as e:
    print(f"7. Training page: ❌ FAIL (Error: {e})")

# 8. Test settings page
try:
    response = session.get('http://127.0.0.1:5000/settings')
    print(f"8. Settings page: {'✅ PASS' if response.status_code == 200 else '❌ FAIL'} (Status: {response.status_code})")
except Exception as e:
    print(f"8. Settings page: ❌ FAIL (Error: {e})")

# 9. Test profile page
try:
    response = session.get('http://127.0.0.1:5000/profile')
    print(f"9. Profile page: {'✅ PASS' if response.status_code == 200 else '❌ FAIL'} (Status: {response.status_code})")
except Exception as e:
    print(f"9. Profile page: ❌ FAIL (Error: {e})")

# 10. Test admin page (only for admin users)
try:
    response = session.get('http://127.0.0.1:5000/admin')
    print(f"10. Admin page: {'✅ PASS' if response.status_code == 200 else '❌ FAIL'} (Status: {response.status_code})")
except Exception as e:
    print(f"10. Admin page: ❌ FAIL (Error: {e})")

# 11. Test CSV export
try:
    response = session.get('http://127.0.0.1:5000/export_csv')
    # CSV export should return 200 or redirect to login if not authenticated
    print(f"11. CSV export: {'✅ PASS' if response.status_code == 200 else '⚠️  CHECK'} (Status: {response.status_code})")
except Exception as e:
    print(f"11. CSV export: ❌ FAIL (Error: {e})")

# 12. Test file upload functionality
print("\n=== TESTING FILE UPLOAD FUNCTIONALITY ===")
try:
    # First, let's check if we can access the upload endpoint
    response = session.options('http://127.0.0.1:5000/upload')
    print(f"12. Upload endpoint access: {'✅ PASS' if response.status_code in [200, 405] else '❌ FAIL'} (Status: {response.status_code})")
except Exception as e:
    print(f"12. Upload endpoint access: ❌ FAIL (Error: {e})")

# 13. Test logout functionality
try:
    response = session.get('http://127.0.0.1:5000/logout')
    print(f"13. Logout functionality: {'✅ PASS' if response.status_code in [200, 302] else '❌ FAIL'} (Status: {response.status_code})")
except Exception as e:
    print(f"13. Logout functionality: ❌ FAIL (Error: {e})")

print("\n=== TEST COMPLETED ===")