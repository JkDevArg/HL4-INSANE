import sqlite3
import os
import hashlib

DB_PATH = "/app/data/erp.db"
FLAG = os.environ.get("FLAG", "HL4{EJEMPLO_LOCAL}")


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def init():
    os.makedirs("/app/data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS orders;
        DROP TABLE IF EXISTS inventory;
        DROP TABLE IF EXISTS flags;
        DROP TABLE IF EXISTS config;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            email TEXT
        );

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer TEXT NOT NULL,
            product TEXT NOT NULL,
            quantity INTEGER DEFAULT 1,
            status TEXT DEFAULT 'pending',
            total REAL DEFAULT 0.0,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product TEXT NOT NULL,
            stock INTEGER DEFAULT 0,
            price REAL DEFAULT 0.0
        );

        CREATE TABLE flags (
            id INTEGER PRIMARY KEY,
            flag_value TEXT NOT NULL
        );

        CREATE TABLE config (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    """)

    # Users - passwords stored as plain text for simplicity (MD5 "hash" is decorative)
    users = [
        ("admin",   "Admin@2024!",   "admin",   "admin@erp.corp"),
        ("manager", "Manager!789",   "manager", "manager@erp.corp"),
        ("user1",   "User1pass",     "user",    "user1@erp.corp"),
        ("viewer",  "View3r!only",   "user",    "viewer@erp.corp"),
    ]
    for u in users:
        c.execute(
            "INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)", u
        )

    # Sample orders
    orders = [
        ("Empresa Alpha S.A.C.",     "Laptop Dell XPS 15",          3,  "completed", 18750.00),
        ("Grupo Beta Corp.",          "Monitor 4K 27\"",              10, "pending",   23500.00),
        ("Inversiones Gamma EIRL",   "Servidor Rack 2U",             1,  "processing",67200.00),
        ("Comercial Delta SAC",       "Switch 48p PoE",               2,  "completed", 14800.00),
        ("Holdings Epsilon S.A.",    "Router BGP Enterprise",        1,  "pending",   38900.00),
        ("TechCorp Peru",            "Access Point WiFi 6",          20, "completed", 31600.00),
        ("Distribuidora Zeta",       "UPS 3KVA",                     5,  "processing", 8750.00),
        ("Servicios Eta SAC",        "SSD NVMe 2TB",                 50, "pending",   12500.00),
    ]
    for o in orders:
        c.execute(
            "INSERT INTO orders (customer, product, quantity, status, total) VALUES (?,?,?,?,?)", o
        )

    # Inventory
    inventory = [
        ("Laptop Dell XPS 15",     15,  6250.00),
        ("Monitor 4K 27\"",          8,  2350.00),
        ("Servidor Rack 2U",        3, 67200.00),
        ("Switch 48p PoE",         12,  7400.00),
        ("Router BGP Enterprise",   5, 38900.00),
        ("Access Point WiFi 6",    30,  1580.00),
        ("UPS 3KVA",               20,  1750.00),
        ("SSD NVMe 2TB",          100,   250.00),
    ]
    for i in inventory:
        c.execute("INSERT INTO inventory (product, stock, price) VALUES (?,?,?)", i)

    # Flag
    c.execute("INSERT INTO flags (id, flag_value) VALUES (1, ?)", (FLAG,))

    # Config
    config = [
        ("backup_path",   "/app/backups/"),
        ("app_version",   "3.2.1"),
        ("company_name",  "ERP Corporativo"),
        ("max_upload_mb", "10"),
        ("db_version",    "SQLite 3.x"),
    ]
    for k, v in config:
        c.execute("INSERT INTO config (key, value) VALUES (?,?)", (k, v))

    conn.commit()
    conn.close()
    print("[*] Database initialized at", DB_PATH)


if __name__ == "__main__":
    init()
