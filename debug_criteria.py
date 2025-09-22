import sqlite3

def debug_current_criteria():
    """Debug script to see what's in the current criteria"""
    print("="*60)
    print("DEBUGGING CURRENT CRITERIA")
    print("="*60)
    
    conn = sqlite3.connect('candidates.db')
    c = conn.cursor()
    
    try:
        # Get current criteria
        c.execute('SELECT * FROM criteria WHERE is_active = 1 ORDER BY created_date DESC LIMIT 1')
        current_criteria = c.fetchone()
        
        print(f"Raw criteria row: {current_criteria}")
        print(f"Row length: {len(current_criteria) if current_criteria else 0}")
        
        if current_criteria:
            print("\nIndexed breakdown:")
            for i, value in enumerate(current_criteria):
                print(f"  Index {i}: {repr(value)} (type: {type(value).__name__})")
        
        # Also check the table structure
        c.execute("PRAGMA table_info(criteria)")
        columns = c.fetchall()
        print(f"\nTable structure:")
        for col in columns:
            print(f"  {col[0]}: {col[1]} ({col[2]})")
            
        # Show all criteria rows for context
        c.execute('SELECT * FROM criteria')
        all_criteria = c.fetchall()
        print(f"\nAll criteria rows ({len(all_criteria)} total):")
        for i, row in enumerate(all_criteria):
            print(f"  Row {i+1}: {row}")
            print(f"    Length: {len(row)}, Active: {row[-2] if len(row) > 1 else 'unknown'}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    debug_current_criteria()
