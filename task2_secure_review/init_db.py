import sqlite3
import os
from werkzeug.security import generate_password_hash

def init_database():
    db_path = "users.db"
    
    # Remove existing db if it exists to start fresh
    if os.path.exists(db_path):
        os.remove(db_path)
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,          -- Plaintext password (vulnerable app check)
        password_hash TEXT NOT NULL      -- Hashed password (secure app check)
    )
    """)
    
    # Insert mock users
    mock_users = [
        ("admin", "admin123", generate_password_hash("admin123")),
        ("alice", "supersecure99", generate_password_hash("supersecure99")),
        ("bob", "password123", generate_password_hash("password123"))
    ]
    
    cursor.executemany("""
    INSERT INTO users (username, password, password_hash)
    VALUES (?, ?, ?)
    """, mock_users)
    
    conn.commit()
    conn.close()
    print("[*] SQLite database 'users.db' initialized successfully with 3 users.")

if __name__ == "__main__":
    init_database()
