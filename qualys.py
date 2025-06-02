import requests
import pandas as pd
import os
import sys
from requests.auth import HTTPBasicAuth
from datetime import datetime
import logging
import urllib3
import xml.etree.ElementTree as ET
from io import StringIO

# Suppress SSL warnings if needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('qualys_gav_api.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class QualysGAVClient:
    def __init__(self, base_url, username, password):
        """
        Initialize Qualys GAV API client
        
        Args:
            base_url: Qualys API base URL (region-specific)
            username: Qualys username
            password: Qualys password
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session_id = None
        
        # Set up session with authentication
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.headers.update({
            'X-Requested-With': 'Python requests',
            'User-Agent': 'QualysGAV-Python-Client/1.0'
        })
        
        # Login to get session
        self.login()
    
    def login(self):
        """
        Login to Qualys platform to establish session
        """
        login_url = f'{self.base_url}/api/2.0/fo/session/'
        
        login_data = {
            'action': 'login',
            'username': self.username,
            'password': self.password
        }
        
        try:
            response = self.session.post(
                login_url,
                data=login_data,
                verify=True,
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info("✅ Successfully logged into Qualys platform")
                return True
            else:
                logger.error(f"❌ Login failed: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Login request failed: {e}")
            return False
    
    def logout(self):
        """
        Logout from Qualys platform
        """
        logout_url = f'{self.base_url}/api/2.0/fo/session/'
        
        logout_data = {
            'action': 'logout'
        }
        
        try:
            response = self.session.post(
                logout_url,
                data=logout_data,
                verify=True,
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info("✅ Successfully logged out from Qualys platform")
            else:
                logger.warning(f"⚠️ Logout response: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Logout request failed: {e}")
    
    def search_assets_with_software_exclude_version(self, application_name, excluded_version):
        """
        Search for assets that have specific software but NOT a specific version
        Query: software:(name: Application Name) and not software:(version: Application version)
        
        Args:
            application_name: Name of the software to search for
            excluded_version: Version to exclude from results
        """
        # GAV asset search endpoint
        search_url = f'{self.base_url}/qps/rest/2.0/search/am/asset'
        
        # XML search body with software name inclusion and version exclusion
        xml_data = f"""
<ServiceRequest>
  <filters>
    <Criteria field="software.name" operator="CONTAINS">{application_name}</Criteria>
    <Criteria field="software.version" operator="NOT_EQUALS">{excluded_version}</Criteria>
  </filters>
</ServiceRequest>
"""
        
        headers = {
            'Content-Type': 'application/xml',
            'X-Requested-With': 'Python requests'
        }
        
        logger.info(f"🔍 Searching for software: {application_name}")
        logger.info(f"❌ Excluding version: {excluded_version}")
        logger.info(f"GAV Search URL: {search_url}")
        logger.info(f"Query Logic: software:(name: {application_name}) and not software:(version: {excluded_version})")
        
        try:
            response = self.session.post(
                search_url,
                headers=headers,
                data=xml_data,
                verify=True,
                timeout=300
            )
            
            logger.info(f"GAV API Response Status: {response.status_code}")
            
            if response.status_code == 200:
                return response.text
            else:
                logger.error(f"GAV API Error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"GAV search request failed: {e}")
            return None
    
    def search_assets_with_software_exclude_version_advanced(self, application_name, excluded_version):
        """
        Advanced search using GAV query syntax with logical operators
        This method uses the native GAV query format for more precise control
        
        Args:
            application_name: Name of the software to search for
            excluded_version: Version to exclude from results
        """
        # GAV asset search endpoint
        search_url = f'{self.base_url}/qps/rest/2.0/search/am/asset'
        
        # Advanced XML with GAV query syntax
        gav_query = f'software:(name:"{application_name}") and not software:(version:"{excluded_version}")'
        
        xml_data = f"""
<ServiceRequest>
  <preferences>
    <limitResults>1000</limitResults>
  </preferences>
  <filters>
    <Criteria field="qgSearch" operator="EQUALS">{gav_query}</Criteria>
  </filters>
</ServiceRequest>
"""
        
        headers = {
            'Content-Type': 'application/xml',
            'X-Requested-With': 'Python requests'
        }
        
        logger.info(f"🔍 Advanced GAV Query: {gav_query}")
        logger.info(f"GAV Search URL: {search_url}")
        
        try:
            response = self.session.post(
                search_url,
                headers=headers,
                data=xml_data,
                verify=True,
                timeout=300
            )
            
            logger.info(f"GAV API Response Status: {response.status_code}")
            
            if response.status_code == 200:
                return response.text
            else:
                logger.error(f"GAV API Error: {response.status_code} - {response.text}")
                # Fallback to basic method if advanced fails
                logger.info("🔄 Falling back to basic search method...")
                return self.search_assets_with_software_exclude_version(application_name, excluded_version)
                
        except requests.exceptions.RequestException as e:
            logger.error(f"GAV advanced search request failed: {e}")
            # Fallback to basic method
            logger.info("🔄 Falling back to basic search method...")
            return self.search_assets_with_software_exclude_version(application_name, excluded_version)
    
    def get_asset_details(self, asset_id):
        """
        Get detailed information for a specific asset
        
        Args:
            asset_id: Asset ID to get details for
        """
        details_url = f'{self.base_url}/qps/rest/2.0/get/am/asset/{asset_id}'
        
        headers = {
            'Content-Type': 'application/xml',
            'X-Requested-With': 'Python requests'
        }
        
        logger.info(f"Getting details for asset ID: {asset_id}")
        
        try:
            response = self.session.get(
                details_url,
                headers=headers,
                verify=True,
                timeout=300
            )
            
            if response.status_code == 200:
                return response.text
            else:
                logger.error(f"Asset details API Error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Asset details request failed: {e}")
            return None

def parse_gav_xml_response(xml_response):
    """
    Parse GAV XML response and extract asset information
    
    Args:
        xml_response: XML response from GAV API
    """
    if not xml_response:
        return None
    
    try:
        root = ET.fromstring(xml_response)
        assets_data = []
        
        # Find all asset elements
        for asset in root.findall('.//Asset'):
            asset_info = {}
            
            # Extract basic asset information
            asset_info['Asset_ID'] = asset.get('id', '')
            
            # Extract asset fields
            for tag in asset.findall('.//tag'):
                tag_name = tag.get('name', '')
                tag_value = tag.text if tag.text else ''
                asset_info[tag_name] = tag_value
            
            assets_data.append(asset_info)
        
        logger.info(f"Parsed {len(assets_data)} assets from XML response")
        return assets_data
        
    except ET.ParseError as e:
        logger.error(f"Error parsing XML response: {e}")
        logger.debug(f"XML Response: {xml_response[:500]}...")
        return None
    except Exception as e:
        logger.error(f"Unexpected error parsing XML: {e}")
        return None

def create_dataframe_from_assets(assets_data):
    """
    Create pandas DataFrame from parsed asset data with focus on software information
    
    Args:
        assets_data: List of asset dictionaries
    """
    if not assets_data:
        return None
    
    try:
        df = pd.DataFrame(assets_data)
        logger.info(f"Created DataFrame with {len(df)} rows and {len(df.columns)} columns")
        
        # Log software-related columns if they exist
        software_columns = [col for col in df.columns if 'software' in col.lower() or 'version' in col.lower()]
        if software_columns:
            logger.info(f"Software-related columns found: {software_columns}")
        
        logger.info(f"All available columns: {list(df.columns)}")
        return df
        
    except Exception as e:
        logger.error(f"Error creating DataFrame: {e}")
        return None

def create_email_draft(application_name, excluded_version, csv_file_path, asset_count=0):
    """
    Create email draft with attachment for software exclusion search
    
    Args:
        application_name: Software name searched
        excluded_version: Version that was excluded
        csv_file_path: Path to CSV file
        asset_count: Number of assets found
    """
    try:
        import win32com.client as win32
        
        outlook = win32.Dispatch('Outlook.Application')
        mail = outlook.CreateItem(0)
        
        mail.Subject = f'Qualys GAV Report: {application_name} (Excluding v{excluded_version})'
        
        mail.Body = f'''Dear Security Team,

Please find attached the Qualys GAV asset report for software inventory analysis:

Search Details:
- Software Name: {application_name}
- Excluded Version: {excluded_version}
- Query Used: software:(name: {application_name}) and not software:(version: {excluded_version})
- Assets Found: {asset_count}
- Report Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- Platform: Qualys India (qg1.apps.qualys.in)
- API: Global Asset View (GAV)

Purpose: This report identifies all assets that have {application_name} installed but NOT version {excluded_version}.
This is useful for:
- Version compliance checks
- Identifying outdated software installations
- Security patch management
- License compliance auditing

Please review the attached asset report and take necessary remediation actions.

Best regards,
Automated Security Reporting System

---
This email was generated automatically by the Qualys GAV Asset Management script.
Query: software:(name: {application_name}) and not software:(version: {excluded_version})
Region: India
'''
        
        # Attach the CSV file
        if os.path.exists(csv_file_path):
            attachment_path = os.path.abspath(csv_file_path)
            mail.Attachments.Add(attachment_path)
            logger.info(f"Attached file: {attachment_path}")
        
        # Save as draft
        mail.Save()
        logger.info("✅ Draft email created successfully in Outlook")
        
    except ImportError:
        logger.error("❌ win32com.client not available. Email draft creation skipped.")
        logger.info("💡 Install pywin32: pip install pywin32")
    except Exception as e:
        logger.error(f"❌ Error creating email draft: {e}")

def main():
    """
    Main function to execute the Qualys GAV software search with version exclusion
    """
    # Configuration - Replace with your actual values
    CONFIG = {
        'QUALYS_BASE_URL': 'https://qualysapi.qg1.apps.qualys.in',  # India platform - qg1
        'USERNAME': 'your_username',
        'PASSWORD': 'your_password',
        'APPLICATION_NAME': 'Chrome',      # Software to search for
        'EXCLUDED_VERSION': '120.0.6099.109',  # Version to exclude
        'USE_ADVANCED_SEARCH': True,       # Try advanced GAV query first
    }
    
    # Initialize Qualys GAV client
    gav_client = QualysGAVClient(
        base_url=CONFIG['QUALYS_BASE_URL'],
        username=CONFIG['USERNAME'],
        password=CONFIG['PASSWORD']
    )
    
    logger.info("🚀 Starting Qualys GAV software search with version exclusion...")
    logger.info(f"Platform: India ({CONFIG['QUALYS_BASE_URL']})")
    logger.info(f"Target Query: software:(name: {CONFIG['APPLICATION_NAME']}) and not software:(version: {CONFIG['EXCLUDED_VERSION']})")
    
    xml_response = None
    
    try:
        # Execute the search with version exclusion
        if CONFIG['USE_ADVANCED_SEARCH']:
            xml_response = gav_client.search_assets_with_software_exclude_version_advanced(
                CONFIG['APPLICATION_NAME'], 
                CONFIG['EXCLUDED_VERSION']
            )
        else:
            xml_response = gav_client.search_assets_with_software_exclude_version(
                CONFIG['APPLICATION_NAME'], 
                CONFIG['EXCLUDED_VERSION']
            )
        
        if not xml_response:
            logger.error("❌ No data retrieved from Qualys GAV API")
            return
        
        # Save raw XML response
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        search_identifier = f"{CONFIG['APPLICATION_NAME']}_exclude_v{CONFIG['EXCLUDED_VERSION']}"
        raw_xml_filename = f'qualys_gav_raw_{search_identifier}_{timestamp}.xml'
        
        with open(raw_xml_filename, 'w', encoding='utf-8') as file:
            file.write(xml_response)
        logger.info(f"Raw XML response saved to: {raw_xml_filename}")
        
        # Parse XML response
        assets_data = parse_gav_xml_response(xml_response)
        
        if assets_data:
            # Create DataFrame
            df = create_dataframe_from_assets(assets_data)
            
            if df is not None and not df.empty:
                # Save to CSV
                csv_filename = f'qualys_gav_assets_{search_identifier}_{timestamp}.csv'
                df.to_csv(csv_filename, index=False)
                logger.info(f"Asset data saved to: {csv_filename}")
                
                # Display summary
                asset_count = len(df)
                logger.info(f"✅ Found {asset_count} assets with {CONFIG['APPLICATION_NAME']} (excluding version {CONFIG['EXCLUDED_VERSION']})")
                
                # Show sample data
                if asset_count > 0:
                    logger.info("Sample of found assets:")
                    print(df.head().to_string())
                    
                    # Show software version distribution if available
                    version_columns = [col for col in df.columns if 'version' in col.lower()]
                    if version_columns:
                        logger.info("\nSoftware version distribution:")
                        for col in version_columns[:3]:  # Show first 3 version columns
                            if col in df.columns:
                                version_counts = df[col].value_counts().head(10)
                                logger.info(f"{col}:\n{version_counts}")
                
                # Create email draft
                create_email_draft(
                    application_name=CONFIG['APPLICATION_NAME'],
                    excluded_version=CONFIG['EXCLUDED_VERSION'],
                    csv_file_path=csv_filename,
                    asset_count=asset_count
                )
                
            else:
                logger.warning(f"No assets found with {CONFIG['APPLICATION_NAME']} (excluding version {CONFIG['EXCLUDED_VERSION']})")
        else:
            logger.warning("Could not parse XML response or no assets found")
            logger.info("Check the raw XML file for manual review")
    
    finally:
        # Logout from Qualys
        gav_client.logout()

if __name__ == "__main__":
    main()
