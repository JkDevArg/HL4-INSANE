import sqlite3
import os

FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')
DB_PATH = '/app/data/portal.db'

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    price REAL
)''')

c.execute('''CREATE TABLE IF NOT EXISTS flags (
    id INTEGER PRIMARY KEY,
    secret TEXT NOT NULL
)''')

c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
)''')

products = [
    ('Laptop Pro X1', 'Electronics', 'High performance laptop', 1299.99),
    ('Wireless Mouse', 'Electronics', 'Ergonomic wireless mouse', 29.99),
    ('Office Chair', 'Furniture', 'Ergonomic office chair', 299.99),
    ('Monitor 4K', 'Electronics', '27 inch 4K display', 599.99),
    ('Keyboard MX', 'Electronics', 'Mechanical keyboard', 149.99),
    ('Standing Desk', 'Furniture', 'Adjustable standing desk', 499.99),
    ('USB Hub', 'Electronics', '7-port USB 3.0 hub', 39.99),
    ('Webcam HD', 'Electronics', '1080p HD webcam', 79.99),
]
c.executemany('INSERT OR IGNORE INTO products (name, category, description, price) VALUES (?,?,?,?)', products)

c.execute('INSERT OR IGNORE INTO flags (id, secret) VALUES (1, ?)', (FLAG,))
c.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?,?,?)',
          ('admin', 'SuperAdmin!2024', 'admin'))
c.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?,?,?)',
          ('user1', 'User1pass!', 'user'))
c.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?,?,?)',
          ('guest', 'guest123', 'guest'))

conn.commit()
conn.close()
print(f"Database initialized at {DB_PATH}")
