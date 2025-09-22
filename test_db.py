import sqlite3

def check_database():
    conn = sqlite3.connect('candidates.db')
    cursor = conn.cursor()
    
    # Check tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [t[0] for t in cursor.fetchall()]
    print('Tables:', tables)
    
    # Check criteria table schema
    if 'criteria' in tables:
        cursor.execute('PRAGMA table_info(criteria)')
        cols = cursor.fetchall()
        print('\nCriteria table columns:')
        for col in cols:
            print(f'  {col[1]} ({col[2]})')
        
        # Check current data
        cursor.execute('SELECT id, position_title, job_status, is_active FROM criteria')
        data = cursor.fetchall()
        print(f'\nCurrent criteria ({len(data)} rows):')
        for row in data:
            print(f'  ID: {row[0]}, Position: {row[1]}, Status: {row[2]}, Active: {row[3]}')
    
    # Check candidates table
    if 'candidates' in tables:
        cursor.execute('SELECT COUNT(*) FROM candidates')
        count = cursor.fetchone()[0]
        print(f'\nTotal candidates: {count}')
    
    conn.close()

if __name__ == '__main__':
    check_database()
