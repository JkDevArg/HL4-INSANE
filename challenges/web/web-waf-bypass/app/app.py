import sqlite3
import os
import re
import urllib.parse
from flask import Flask, request, jsonify, render_template, session, redirect, make_response

app = Flask(__name__)
app.secret_key = 'waf-secret-key-xyz'
FLAG = os.environ.get('FLAG', 'HL4{EJEMPLO_LOCAL}')
DB_PATH = '/app/data/portal.db'

# Custom WAF: blocks common SQLi patterns
WAF_PATTERNS = [
    r'\bunion\b',
    r'\bselect\b',
    r'--',
    r'\bor\b',
    r'\band\b',
    r'\bsleep\b',
    r'\bbenchmark\b',
    r'\bwaitfor\b',
    r'\bdrop\b',
    r'\bdelete\b',
    r'\binsert\b',
    r'\bupdate\b',
    r'\/\*',
    r'\*\/',
    r'\bload_file\b',
    r'\boutfile\b',
    r'\binformation_schema\b',
    r"'--",
    r'1=1',
]

def waf_check(value):
    """Check if value contains SQLi patterns. Returns True if blocked."""
    if not value:
        return False
    # Decode URL encoding once (Flask has already decoded once)
    decoded = urllib.parse.unquote(str(value))
    for pattern in WAF_PATTERNS:
        if re.search(pattern, decoded, re.IGNORECASE):
            return True
    return False

def check_all_inputs():
    """Check all URL query params and form data through WAF. JSON body is NOT checked."""
    for key, value in request.args.items():
        if waf_check(value):
            return True
    for key, value in request.form.items():
        if waf_check(value):
            return True
    return False

@app.before_request
def waf_middleware():
    # WAF only applies to GET/POST form requests, NOT JSON API endpoints
    if request.endpoint in ('api_search',):
        return None  # Skip WAF for /api/search (JSON body not checked)
    if check_all_inputs():
        return make_response(
            '<html><body><h2 style="color:red">WAF: Suspicious request blocked (403)</h2>'
            '<p>Your request has been logged and flagged for security review.</p>'
            '<a href="/">Return to search</a></body></html>',
            403
        )

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search')
def search():
    query = request.args.get('q', '')
    category = request.args.get('cat', '')
    results = []
    error = None
    sql_debug = None

    if query or category:
        try:
            conn = get_db()
            c = conn.cursor()
            # VULNERABLE: Direct string interpolation - but WAF blocks common patterns
            sql_query = f"SELECT id, name, category, description, price FROM products WHERE name LIKE '%{query}%'"
            if category:
                sql_query += f" AND category = '{category}'"

            sql_debug = sql_query
            c.execute(sql_query)
            rows = c.fetchall()
            results = [dict(r) for r in rows]
            conn.close()
        except Exception as e:
            error = str(e)

    return render_template('search.html', results=results, query=query,
                           category=category, error=error, sql_debug=sql_debug)

@app.route('/api/search', methods=['POST'])
def api_search():
    """
    API search endpoint - accepts JSON body.
    WAF is NOT applied to this endpoint (JSON body bypass).
    This is the vulnerable path.
    """
    data = request.get_json() or {}
    query = data.get('q', '')
    category = data.get('cat', '')
    results = []
    error = None

    try:
        conn = get_db()
        c = conn.cursor()
        # VULNERABLE: direct string interpolation, no WAF protection on JSON body
        sql_query = f"SELECT id, name, category, description, price FROM products WHERE name LIKE '%{query}%'"
        if category:
            sql_query += f" AND category = '{category}'"

        c.execute(sql_query)
        rows = c.fetchall()
        results = [dict(r) for r in rows]
        conn.close()
    except Exception as e:
        error = str(e)

    return jsonify({'results': results, 'count': len(results), 'error': error})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT id, username, role FROM users WHERE username=? AND password=?',
                  (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['user'] = user['username']
            session['role'] = user['role']
            return redirect('/')
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
