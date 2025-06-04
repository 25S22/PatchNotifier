#!/usr/bin/env python3
import requests
import pandas as pd
import sys
import os

# ─────── CONFIGURATION ────────── #
# 1) Use your India API server (as seen under Help → About in the UI)
API_SERVER = 'https://qualysapi.qg1.apps.qualys.in'  
USERNAME   = 'YOUR_QUALYS_USERNAME'    # fill in
PASSWORD   = 'YOUR_QUALYS_PASSWORD'    # fill in

# SSL_VERIFY can be True (use system CAs), False (no verification), or path to your cert bundle.
SSL_VERIFY = True  

# ─────── SCRIPT INPUT: Software Name & Version ────────── #
# Provide these two values via command‐line args.
if len(sys.argv) != 3:
    print("Usage: python fetch_hosts_by_software.py <AppName> <AppVersion>")
    sys.exit(1)

APP_NAME    = sys.argv[1]  # e.g. "ExampleApp"
APP_VERSION = sys.argv[2]  # e.g. "1.2.3"


# ─────── STEP 1: LOGIN → OBTAIN QualysSession COOKIE ────────── #
def get_session_cookie(api_server, user, pwd, verify_ssl):
    """
    POST to /api/2.0/fo/session/?action=login
    Returns a dict like {'QualysSession': '<SESSION_ID>'} on success.
    """
    login_url = f'{api_server}/api/2.0/fo/session/'
    headers = {
        'X-Requested-With': 'PythonScript'  
    }
    data = {
        'action': 'login',
        'username': user,
        'password': pwd
    }

    try:
        resp = requests.post(login_url, headers=headers, data=data, verify=verify_ssl)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f'❌ Session login failed: {e}')
        sys.exit(1)

    # Qualys returns Set-Cookie: QualysSession=<VALUE>; path=/api; secure
    cookie_dict = resp.cookies.get_dict()
    session_id = cookie_dict.get('QualysSession')
    if not session_id:
        print("❌ ERROR: 'QualysSession' cookie not found in login response.")
        sys.exit(1)

    print("✅ Logged in. Got QualysSession cookie.")
    return {'QualysSession': session_id}


# ─────── STEP 2: CALL ASSET API w/ softwareName & softwareVersion ────────── #
def fetch_hosts_by_software(api_server, cookies, app_name, app_version, verify_ssl):
    """
    Calls /api/2.0/fo/asset/host/?action=list 
    with softwareName & softwareVersion filters.
    Returns the raw CSV text from Qualys (or raises on failure).
    """
    asset_url = f'{api_server}/api/2.0/fo/asset/host/'
    params = {
        'action': 'list',
        # Output as CSV; you could also request JSON: 'output_format': 'JSON'
        'output_format': 'CSV',
        'details': 'All',
        'softwareName': app_name,
        'softwareVersion': app_version
    }
    headers = {
        'X-Requested-With': 'PythonScript'
    }

    try:
        resp = requests.post(asset_url, headers=headers, params=params, cookies=cookies, verify=verify_ssl)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f'❌ Asset list API failed: {e}')
        if resp is not None:
            print("Response text:", resp.text)
        sys.exit(1)

    return resp.text  # raw CSV


# ─────── STEP 3: SAVE CSV & (optional) LOAD INTO PANDAS ────────── #
def save_and_show_csv(csv_text, filename='hosts_with_software.csv'):
    """
    Saves the CSV response to disk and also prints how many lines/rows it contains.
    """
    with open(filename, 'w', newline='') as f:
        f.write(csv_text)
    print(f"✅ Saved CSV to {os.path.abspath(filename)}")

    # Quick check with pandas to count rows (excluding header)
    try:
        df = pd.read_csv(filename)
        print(f"ℹ️  Retrieved {len(df)} host(s) matching the filter.")
    except Exception as e:
        print(f"⚠️ Could not parse CSV with pandas: {e}")


# ─────── MAIN ────────── #
if __name__ == '__main__':
    # 1. Get session cookie
    cookies = get_session_cookie(API_SERVER, USERNAME, PASSWORD, SSL_VERIFY)

    # 2. Fetch only hosts that have APP_NAME @ APP_VERSION
    csv_data = fetch_hosts_by_software(API_SERVER, cookies, APP_NAME, APP_VERSION, SSL_VERIFY)

    # 3. Save and show results
    save_and_show_csv(csv_data)
