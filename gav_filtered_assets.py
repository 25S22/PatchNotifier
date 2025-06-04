#!/usr/bin/env python3
import requests
import pandas as pd
import urllib.parse
import sys
import os
import json

# ─────── CONFIGURATION ────────── #
# Replace with your GAV gateway URL. 
# For India, it's usually "https://gateway.qg1.apps.qualys.in"
# or check “Help ➔ About” in your Qualys UI to confirm.
GAV_BASE_URL = 'https://gateway.qg1.apps.qualys.in'  # 2

# Your Qualys credentials (API user with “GAV Asset → Read” permission)
USERNAME = 'YOUR_QUALYS_USERNAME'
PASSWORD = 'YOUR_QUALYS_PASSWORD'

# SSL certificate / CA bundle for verification. 
# - Use True to verify against system CAs
# - Or set to the path of your cert.pem
SSL_VERIFY = True  # or '/path/to/your/cert.pem'

# ─────── INPUT: Application Name & Version ────────── #
# These can be hard-coded, or later passed in via sys.argv when used as a subprocess.
APPLICATION_NAME = 'ExampleApp'
APPLICATION_VERSION = '1.2.3'

# ─────── STEP 1: Authenticate and get JWT ────────── #
def get_jwt_token(base_url, user, pwd, verify):
    """
    Calls POST {base_url}/auth with form data (username, password, token=true) 
    and returns the JWT on success. Exits if authentication fails.
    """
    auth_url = f'{base_url}/auth'
    auth_headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    auth_data = {
        'username': user,
        'password': pwd,
        'token': 'true'
    }

    try:
        resp = requests.post(
            auth_url,
            headers=auth_headers,
            data=auth_data,
            verify=verify
        )
    except requests.exceptions.RequestException as e:
        print(f'❌ ERROR: Could not connect to {auth_url}: {e}')
        sys.exit(1)

    if resp.status_code != 200:
        print(f'❌ Authentication failed (HTTP {resp.status_code}): {resp.text}')
        sys.exit(1)

    # Qualys returns JSON like:
    #   {
    #     "status": "SUCCESS",
    #     "data": { "token": "<JWT_TOKEN>", … }
    #   }
    # or sometimes:
    #   { "token": "<JWT_TOKEN>", … }
    try:
        payload = resp.json()
    except json.JSONDecodeError:
        print(f'❌ ERROR: Authentication response is not valid JSON:\n{resp.text}')
        sys.exit(1)

    token = None
    if isinstance(payload, dict):
        if 'data' in payload and isinstance(payload['data'], dict):
            token = payload['data'].get('token')
        if not token and 'token' in payload:
            token = payload['token']

    if not token:
        print('❌ ERROR: Could not extract JWT from response. Full payload:')
        print(json.dumps(payload, indent=2))
        sys.exit(1)

    print('✅ Obtained JWT token.')
    return token


# ─────── STEP 2: Fetch Filtered Assets ────────── #
def fetch_filtered_assets(base_url, jwt, app_name, app_version, verify):
    """
    Builds a filter for software:(name:"<app_name>" AND version:"<app_version>"),
    calls POST {base_url}/am/v1/assets/host/filter/list?filter=<encoded_filter>&includeFields=...
    and returns the JSON response. Exits on HTTP error.
    """
    # 1. Build the “software:” filter string
    #    E.g.: software:(name:"ExampleApp" AND version:"1.2.3")
    raw_filter = f'software:(name:"{app_name}" AND version:"{app_version}")'
    # 2. URL-encode the filter
    encoded_filter = urllib.parse.quote(raw_filter, safe='')
    # 3. Build the full URL with filter and includeFields
    #    We only need a few fields: assetId, assetHostName, operatingSystem, status.
    assets_url = (
        f'{base_url}/am/v1/assets/host/filter/list'
        f'?filter={encoded_filter}'
        f'&includeFields=assetId,assetHostName,operatingSystem,status'
    )

    headers = {
        'Authorization': f'Bearer {jwt}',
        'Accept': 'application/json'
    }

    try:
        resp = requests.post(
            assets_url,
            headers=headers,
            verify=verify
        )
    except requests.exceptions.RequestException as e:
        print(f'❌ ERROR: Could not connect to {assets_url}: {e}')
        sys.exit(1)

    if resp.status_code != 200:
        print(f'❌ API returned HTTP {resp.status_code}:\n{resp.text}')
        sys.exit(1)

    try:
        return resp.json()
    except json.JSONDecodeError:
        print(f'❌ ERROR: Asset list response is not valid JSON:\n{resp.text}')
        sys.exit(1)


# ─────── MAIN ────────── #
if __name__ == '__main__':
    # 1. Authenticate and get JWT
    jwt_token = get_jwt_token(GAV_BASE_URL, USERNAME, PASSWORD, SSL_VERIFY)

    # 2. Fetch only those assets running APPLICATION_NAME @ APPLICATION_VERSION
    json_payload = fetch_filtered_assets(
        GAV_BASE_URL,
        jwt_token,
        APPLICATION_NAME,
        APPLICATION_VERSION,
        SSL_VERIFY
    )

    # 3. Extract the list of asset objects from the JSON
    #    The “assetListData.asset” array holds each matching asset.
    if (
        'assetListData' in json_payload and
        isinstance(json_payload['assetListData'], dict) and
        'asset' in json_payload['assetListData']
    ):
        asset_list = json_payload['assetListData']['asset']
    else:
        print('⚠️ No "assetListData.asset" key found in response. Full response:')
        print(json.dumps(json_payload, indent=2))
        sys.exit(1)

    print(f'✅ Retrieved {len(asset_list)} matching assets.')

    # 4. Convert to DataFrame and save as CSV
    df = pd.json_normalize(asset_list)
    output_csv = 'filtered_assets.csv'
    df.to_csv(output_csv, index=False)
    print(f'✅ Saved filtered assets to: {os.path.abspath(output_csv)}')
