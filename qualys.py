import requests
import pandas as pd
import os
import sys
from requests.auth import HTTPBasicAuth
from datetime import datetime
import logging
import urllib3

# Suppress SSL warnings if needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('qualys_api.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class QualysAssetSearch:
    def __init__(self, base_url, username, password, platform='US'):
        """
        Initialize Qualys API client
        
        Args:
            base_url: Qualys API base URL (region-specific)
            username: Qualys username
            password: Qualys password
            platform: Platform region (US, EU, etc.)
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.platform = platform
        
        # Set up session with authentication
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.headers.update({
            'X-Requested-With': 'Python Script',
            'User-Agent': f'QualysAPI-Python-Client/1.0'
        })
    
    def search_assets_by_software(self, application_name, application_version=None, 
                                 additional_filters=None, output_format='csv'):
        """
        Search for assets running specific software
        
        Args:
            application_name: Name of the application
            application_version: Version of the application (optional - not used in query)
            additional_filters: Additional search filters
            output_format: Output format (csv, xml)
        """
        # Construct search query - Using only software name as per GAV working query
        search_query = f'software:(name:"{application_name}")'
        
        if additional_filters:
            search_query += f' AND {additional_filters}'
        
        logger.info(f"Searching for assets with query: {search_query}")
        logger.info(f"Note: Searching by software name only. Version filtering will be done post-processing if needed.")
        
        # API endpoint for asset search
        endpoint = f'{self.base_url}/api/2.0/fo/asset/host/'
        
        # Parameters for the search
        params = {
            'action': 'list',
            'output_format': output_format,
            'details': 'All',
            'show_ags': '1',  # Show asset groups
            'show_tags': '1',  # Show asset tags
            'truncation_limit': '1000'  # Increase limit for large datasets
        }
        
        # Add search query if provided
        if search_query:
            params['search_list'] = search_query
        
        try:
            # Make the API request
            response = self.session.post(
                endpoint,
                data=params,
                verify=True,  # Always verify SSL in production
                timeout=300   # 5 minute timeout for large datasets
            )
            
            logger.info(f"API Response Status: {response.status_code}")
            
            if response.status_code == 200:
                return response.content
            else:
                logger.error(f"API Error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return None
    
    def get_host_details(self, host_ids, output_format='csv'):
        """
        Get detailed information for specific hosts
        
        Args:
            host_ids: List of host IDs or single host ID
            output_format: Output format (csv, xml)
        """
        if isinstance(host_ids, list):
            host_ids_str = ','.join(map(str, host_ids))
        else:
            host_ids_str = str(host_ids)
        
        endpoint = f'{self.base_url}/api/2.0/fo/asset/host/'
        
        params = {
            'action': 'list',
            'output_format': output_format,
            'ids': host_ids_str,
            'details': 'All',
            'show_ags': '1',
            'show_tags': '1'
        }
        
        try:
            response = self.session.post(endpoint, data=params, verify=True, timeout=300)
            
            if response.status_code == 200:
                return response.content
            else:
                logger.error(f"Host details API Error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Host details request failed: {e}")
            return None

def process_csv_data(csv_content, desired_columns=None, filter_version=None, app_name=None):
    """
    Process CSV content and filter columns
    
    Args:
        csv_content: Raw CSV content from API
        desired_columns: List of columns to keep
        filter_version: Version to filter by (post-processing)
        app_name: Application name for logging
    """
    if not csv_content:
        return None
    
    try:
        # Create DataFrame from CSV content
        from io import StringIO
        csv_string = csv_content.decode('utf-8')
        df = pd.read_csv(StringIO(csv_string))
        
        logger.info(f"Retrieved {len(df)} records for software: {app_name}")
        logger.info(f"Available columns: {list(df.columns)}")
        
        # Post-process version filtering if needed and version column exists
        if filter_version and 'SOFTWARE' in df.columns:
            original_count = len(df)
            df = df[df['SOFTWARE'].str.contains(filter_version, case=False, na=False)]
            logger.info(f"After version filtering ({filter_version}): {len(df)} records (filtered out {original_count - len(df)})")
        
        # Filter columns if specified
        if desired_columns:
            # Check which desired columns actually exist
            available_columns = [col for col in desired_columns if col in df.columns]
            missing_columns = [col for col in desired_columns if col not in df.columns]
            
            if missing_columns:
                logger.warning(f"Missing columns: {missing_columns}")
                logger.info("Available columns for reference: " + ", ".join(df.columns))
            
            if available_columns:
                df_filtered = df[available_columns]
                return df_filtered
            else:
                logger.error("None of the desired columns are available")
                return df
        
        return df
        
    except Exception as e:
        logger.error(f"Error processing CSV data: {e}")
        return None

def create_email_draft(application_name, application_version, csv_file_path, 
                      asset_count=0):
    """
    Create email draft with attachment (Windows only) - Draft only, no recipients
    
    Args:
        application_name: Application name
        application_version: Application version
        csv_file_path: Path to CSV file
        asset_count: Number of assets found
    """
    try:
        import win32com.client as win32
        
        outlook = win32.Dispatch('Outlook.Application')
        mail = outlook.CreateItem(0)  # 0 = Mail item
        
        mail.Subject = f'Security Advisory: {application_name} Assets Report'
        
        version_text = f' version {application_version}' if application_version else ''
        
        mail.Body = f'''Dear Security Team,

Please find attached the list of assets running {application_name}{version_text}.

Summary:
- Application: {application_name}
- Version: {application_version if application_version else 'All versions'}
- Assets Found: {asset_count}
- Report Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- Search Query Used: software:(name:"{application_name}")

Please review the attached asset list and coordinate patching activities as needed.

Note: This search was performed using software name only. If version-specific filtering is required, 
please review the SOFTWARE column in the attached report.

Best regards,
Automated Security Scanning System

---
This email was generated automatically by the Qualys Asset Management script.
Location: India Qualys Platform
'''
        
        # Attach the CSV file
        if os.path.exists(csv_file_path):
            attachment_path = os.path.abspath(csv_file_path)
            mail.Attachments.Add(attachment_path)
            logger.info(f"Attached file: {attachment_path}")
        
        # Save as draft (no recipients - draft only)
        mail.Save()
        logger.info("✅ Draft email created successfully in Outlook (saved as draft)")
        
    except ImportError:
        logger.error("❌ win32com.client not available. Email draft creation skipped.")
        logger.info("💡 Install pywin32: pip install pywin32")
    except Exception as e:
        logger.error(f"❌ Error creating email draft: {e}")

def main():
    """
    Main function to execute the Qualys asset search
    """
    # Configuration - Replace with your actual values
    CONFIG = {
        'QUALYS_BASE_URL': 'https://qualysapi.qg3.apps.qualys.in',  # India platform
        'USERNAME': 'your_username',
        'PASSWORD': 'your_password',
        'APPLICATION_NAME': 'ExampleApp',  # Replace with actual app name
        'APPLICATION_VERSION': '1.2.3',   # Optional - used for post-filtering and reporting
    }
    
    # Initialize Qualys client
    qualys_client = QualysAssetSearch(
        base_url=CONFIG['QUALYS_BASE_URL'],
        username=CONFIG['USERNAME'],
        password=CONFIG['PASSWORD'],
        platform='IN'
    )
    
    logger.info("Starting Qualys asset search...")
    logger.info(f"Platform: India ({CONFIG['QUALYS_BASE_URL']})")
    logger.info(f"Search Query: software:(name:\"{CONFIG['APPLICATION_NAME']}\")")
    
    # Search for assets using software name only (as per GAV working query)
    csv_content = qualys_client.search_assets_by_software(
        application_name=CONFIG['APPLICATION_NAME'],
        application_version=CONFIG['APPLICATION_VERSION']  # Not used in query, just for reference
    )
    
    if not csv_content:
        logger.error("❌ No data retrieved from Qualys API")
        return
    
    # Save raw CSV
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_csv_filename = f'qualys_assets_raw_{CONFIG["APPLICATION_NAME"]}_{timestamp}.csv'
    
    with open(raw_csv_filename, 'wb') as file:
        file.write(csv_content)
    logger.info(f"Raw data saved to: {raw_csv_filename}")
    
    # Process and filter data
    # These are common Qualys VMDR column names - adjust based on your actual API response
    desired_columns = [
        'IP', 'DNS', 'NETBIOS', 'OS', 'TRACKING_METHOD', 
        'LAST_SCAN_DATETIME', 'LAST_VM_SCANNED_DATE', 
        'ASSET_GROUPS', 'TAGS', 'SOFTWARE'
    ]
    
    df_filtered = process_csv_data(
        csv_content, 
        desired_columns,
        filter_version=CONFIG.get('APPLICATION_VERSION'),  # Post-process version filtering
        app_name=CONFIG['APPLICATION_NAME']
    )
    
    if df_filtered is not None and not df_filtered.empty:
        # Save filtered data
        filtered_csv_filename = f'qualys_assets_filtered_{CONFIG["APPLICATION_NAME"]}_{timestamp}.csv'
        df_filtered.to_csv(filtered_csv_filename, index=False)
        logger.info(f"Filtered data saved to: {filtered_csv_filename}")
        
        # Display summary
        asset_count = len(df_filtered)
        logger.info(f"✅ Found {asset_count} assets running {CONFIG['APPLICATION_NAME']}")
        
        # Show sample data
        if asset_count > 0:
            logger.info("Sample of found assets:")
            print(df_filtered.head().to_string())
        
        # Create email draft (no recipients - draft only)
        create_email_draft(
            application_name=CONFIG['APPLICATION_NAME'],
            application_version=CONFIG.get('APPLICATION_VERSION'),
            csv_file_path=filtered_csv_filename,
            asset_count=asset_count
        )
        
    else:
        logger.warning(f"No assets found running {CONFIG['APPLICATION_NAME']} or error processing data")
        logger.info("💡 Tip: Check if the application name matches exactly as it appears in Qualys GAV")

if __name__ == "__main__":
    main()
