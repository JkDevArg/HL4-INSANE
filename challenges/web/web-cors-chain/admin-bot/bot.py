import requests
import time
import os

ADMIN_TOKEN = 'admin-api-token-secret-abc'
API_URL = 'http://api:8080'

print('[bot] Admin bot started', flush=True)
# Wait for API to be ready
time.sleep(5)


def visit_url(url):
    try:
        r = requests.get(
            url.strip(),
            headers={'Authorization': f'Bearer {ADMIN_TOKEN}'},
            timeout=10,
            allow_redirects=True
        )
        print(f'[bot] Visited {url}: HTTP {r.status_code}', flush=True)
    except Exception as e:
        print(f'[bot] Error visiting {url}: {e}', flush=True)


while True:
    try:
        # Check for pending URLs from the API's shared file
        try:
            with open('/tmp/pending_urls.txt') as f:
                urls = [u.strip() for u in f.readlines() if u.strip()]
            # Clear the file after reading
            with open('/tmp/pending_urls.txt', 'w') as f:
                pass
        except FileNotFoundError:
            urls = []

        for url in urls:
            print(f'[bot] Processing URL: {url}', flush=True)
            visit_url(url)

    except Exception as e:
        print(f'[bot] Error: {e}', flush=True)

    time.sleep(15)
