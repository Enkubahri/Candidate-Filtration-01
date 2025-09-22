import sqlite3
from werkzeug.security import check_password_hash

def test_admin_login(email, password):
    """Test admin login functionality"""
    print(f"Testing login for: {email}")
    
    # Connect to database
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    
    try:
        # Get user by email
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user_data = c.fetchone()
        
        if not user_data:
            print("❌ User not found in database")
            return False
            
        print(f"✓ User found: ID={user_data[0]}, Role={user_data[3]}, Active={user_data[5]}")
        
        # Check if user is admin
        if user_data[3] != 'admin':
            print("❌ User is not an admin")
            return False
            
        print("✓ User has admin role")
        
        # Check if user is active
        if not user_data[5]:
            print("❌ User account is not active")
            return False
            
        print("✓ User account is active")
        
        # Check password
        password_hash = user_data[2]
        if check_password_hash(password_hash, password):
            print("✓ Password is correct")
            return True
        else:
            print("❌ Password is incorrect")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False
    finally:
        conn.close()

# Test the default admin credentials
print("=" * 60)
print("TESTING ADMIN LOGIN")
print("=" * 60)

# Test default admin
print("\n1. Testing default admin credentials:")
print("-" * 40)
success1 = test_admin_login('admin@company.com', 'admin123')

# Test the other admin (we don't know the password, so this will likely fail)
print("\n2. Testing second admin user:")
print("-" * 40)
success2 = test_admin_login('enkugetachew23@gmail.com', 'admin123')

# Try some common passwords for the second user
if not success2:
    print("\n3. Trying other common passwords for second admin:")
    print("-" * 40)
    common_passwords = ['password', '123456', 'admin', 'test123', 'password123']
    for pwd in common_passwords:
        print(f"\nTrying password: {pwd}")
        if test_admin_login('enkugetachew23@gmail.com', pwd):
            success2 = True
            break

print("\n" + "=" * 60)
print("SUMMARY:")
print("=" * 60)
print(f"Default admin (admin@company.com): {'SUCCESS' if success1 else 'FAILED'}")
print(f"Second admin (enkugetachew23@gmail.com): {'SUCCESS' if success2 else 'FAILED'}")
