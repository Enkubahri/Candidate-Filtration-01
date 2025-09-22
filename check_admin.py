import sqlite3

conn = sqlite3.connect('candidates.db')
c = conn.cursor()

try:
    c.execute('SELECT * FROM users WHERE role = "admin"')
    admin_users = c.fetchall()
    
    print('Admin users in database:')
    print('-' * 50)
    
    if admin_users:
        for row in admin_users:
            print(f'ID: {row[0]}')
            print(f'Email: {row[1]}')
            print(f'Password Hash: {row[2][:20]}...')  # Only show first 20 chars
            print(f'Role: {row[3]}')
            print(f'Created Date: {row[4]}')
            print(f'Active: {row[5] if len(row) > 5 else "N/A"}')
            print('-' * 30)
    else:
        print('No admin users found!')
        
    # Also check the table structure
    c.execute("PRAGMA table_info(users)")
    columns = c.fetchall()
    print('\nUsers table structure:')
    print('-' * 50)
    for col in columns:
        print(f'{col[1]} ({col[2]})')
        
except Exception as e:
    print(f'Error: {e}')
finally:
    conn.close()
