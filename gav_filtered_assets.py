import requests
import pandas as pd
import urllib.parse
import sys
import os

# Configuration
AUTH_BASE_URL = 'https://qualysapi.qg1.apps.qualys.in'  # Authentication URL for India
GAV_BASE_URL = 'https://gateway.qg1.apps.qualys.in'     # GAV API base URL for India

USERNAME = 'YOUR_QUALYS_USERNAME'  # Replace with your Qualys username
PASSWORD = 'YOUR_QUALYS_PASSWORD'  # Replace with your Qualys password

SSL_VERIFY = True  # Set to False if you want to disable SSL verification (not recommended)

# Application details
APPLICATION_NAME = 'ExampleApp'    # Replace with your application name
APPLICATION_VERSION = '1.2.3'      # Replace with your application version

def get_jwt_token(auth_url, username, password, verify_ssl):
    """
    Authenticate with Qualys and retrieve JWT token.
    """
    url = f'{auth_url}/auth'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'username': username,
        'password': password,
        'token': 'true'
    }

    try:
        response = requests.post(url, headers=headers, data=data, verify=verify_ssl)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f'Authentication failed: {e}')
        sys.exit(1)

    try:
        token = response.json().get('token')
        if not token:
            print('JWT token not found in the response.')
            sys.exit(1)
        return token
    except ValueError:
        print('Invalid JSON response received during authentication.')
        sys.exit(1)

def fetch_filtered_assets(gav_url, jwt_token, app_name, app_version, verify_ssl):
    """
    Fetch assets filtered by application name and version.
    """
    filter_query = f'software:(name:"{app_name}" AND version:"{app_version}")'
    encoded_filter = urllib.parse.quote(filter_query, safe='')
    endpoint = f'{gav_url}/am/v1/assets/host/filter/list?filter={encoded_filter}&includeFields=assetId,assetHostName,operatingSystem,status'

    headers = {
        'Authorization': f'Bearer {jwt_token}',
        'Accept': 'application/json'
    }

    try:
        response = requests.post(endpoint, headers=headers, verify=verify_ssl)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f'Failed to fetch assets: {e}')
        sys.exit(1)

    try:
        return response.json()
    except ValueError:
        print('Invalid JSON response received when fetching assets.')
        sys.exit(1)

def save_assets_to_csv(asset_data, filename='filtered_assets.csv'):
    """
    Save asset data to a CSV file.
    """
    assets = asset_data.get('assetListData', {}).get('asset', [])
    if not assets:
        print('No assets found matching the filter criteria.')
        return

    df = pd.json_normalize(assets)
    df.to_csv(filename, index=False)
    print(f'Filtered assets saved to {os.path.abspath(filename)}')

def main():
    # Step 1: Authenticate and get JWT token
    jwt_token = get_jwt_token(AUTH_BASE_URL, USERNAME, PASSWORD, SSL_VERIFY)
    print('Authentication successful.')

    # Step 2: Fetch filtered assets
    asset_data = fetch_filtered_assets(GAV_BASE_URL, jwt_token, APPLICATION_NAME, APPLICATION_VERSION, SSL_VERIFY)
    print('Asset data fetched successfully.')

    # Step 3: Save assets to CSV
    save_assets_to_csv(asset_data)

if __name__ == '__main__':
    main()
