import requests
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
import pandas as pd
from packaging import version
import logging
import sys
import os
import win32com.client as win32
from datetime import datetime, timedelta
import json

# === CONFIGURATION ===
USERNAME = "your_qualys_username"
PASSWORD = "your_qualys_password"
CERT_PATH = "/path/to/your/corporate_cert.pem"
BASE_URL = "https://qualysapi.qg1.apps.qualys.in"
PAGE_SIZE = 100
LOG_LEVEL = logging.INFO

# === LOGGER SETUP ===
logger = logging.getLogger("QualysCVESearcher")
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("[%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(LOG_LEVEL)

class QualysCVESearcher:
    def __init__(self, username, password, cert_path, page_size=100):
        self.base_url = BASE_URL.rstrip("/")
        self.session = requests.Session()
        self.auth = HTTPBasicAuth(username, password)
        self.cert_path = cert_path
        self.page_size = page_size
        self.fo_headers = {"X-Requested-With": "Python script"}
        self.qps_headers = {
            "Content-Type": "application/xml",
            "Accept": "application/xml"
        }

    def login(self):
        """Login to Qualys API and establish session"""
        url = f"{self.base_url}/api/2.0/fo/session/"
        data = {
            "action": "login",
            "username": self.auth.username,
            "password": self.auth.password
        }
        logger.info("Logging in...")
        resp = self.session.post(url, headers=self.fo_headers, data=data, verify=self.cert_path)
        resp.raise_for_status()
        if "QualysSession" not in self.session.cookies:
            raise Exception("Login failed.")
        logger.info("Login successful.")

    def logout(self):
        """Logout from Qualys API"""
        url = f"{self.base_url}/api/2.0/fo/session/"
        data = {"action": "logout"}
        try:
            self.session.post(url, headers=self.fo_headers, data=data, verify=self.cert_path)
        except Exception:
            pass
        logger.info("Logged out.")

    def get_qid_from_cve(self, cve_id):
        """
        Get Qualys QID(s) associated with a CVE
        Uses the Knowledge Base API to map CVE to QID
        """
        url = f"{self.base_url}/api/2.0/fo/knowledge_base/vuln/"
        params = {
            "action": "list",
            "details": "All",
            "cve_id": cve_id
        }
        
        logger.info(f"Looking up QID for CVE: {cve_id}")
        resp = self.session.get(url, headers=self.fo_headers, params=params, verify=self.cert_path)
        resp.raise_for_status()
        
        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError:
            raise Exception("Malformed XML response from Knowledge Base API.")
        
        qids = []
        vulns = root.findall(".//VULN")
        
        for vuln in vulns:
            qid = vuln.findtext("QID")
            title = vuln.findtext("TITLE", "")
            severity = vuln.findtext("SEVERITY_LEVEL", "")
            
            if qid:
                qids.append({
                    "qid": qid,
                    "title": title,
                    "severity": severity,
                    "cve": cve_id
                })
        
        if not qids:
            logger.warning(f"No QIDs found for CVE: {cve_id}")
        else:
            logger.info(f"Found {len(qids)} QID(s) for CVE {cve_id}: {[q['qid'] for q in qids]}")
        
        return qids

    def build_vuln_detection_request(self, cve_ids, offset):
        """
        Build XML request for vulnerability detection search using CVEs
        Uses the hostinstancevuln endpoint
        """
        root = ET.Element("ServiceRequest")
        filters = ET.SubElement(root, "filters")
        
        # Create CVE filter - can search multiple CVEs at once
        if len(cve_ids) == 1:
            ET.SubElement(filters, "Criteria", field="cveId", operator="EQUALS").text = cve_ids[0]
        else:
            cve_list = ",".join(cve_ids)
            ET.SubElement(filters, "Criteria", field="cveId", operator="IN").text = cve_list
        
        # Only show active vulnerabilities (not fixed)
        ET.SubElement(filters, "Criteria", field="status", operator="EQUALS").text = "Active"
        
        prefs = ET.SubElement(root, "preferences")
        ET.SubElement(prefs, "startFromOffset").text = str(offset)
        ET.SubElement(prefs, "limitResults").text = str(self.page_size)
        
        # Request specific fields we need
        fields = ET.SubElement(root, "fields")
        
        # Host instance vulnerability fields
        host_vuln = ET.SubElement(fields, "HostInstanceVuln")
        ET.SubElement(host_vuln, "hostInstanceId")
        ET.SubElement(host_vuln, "cveId")
        ET.SubElement(host_vuln, "qid")
        ET.SubElement(host_vuln, "status")
        ET.SubElement(host_vuln, "severity")
        ET.SubElement(host_vuln, "firstFound")
        ET.SubElement(host_vuln, "lastFound")
        ET.SubElement(host_vuln, "port")
        ET.SubElement(host_vuln, "protocol")
        ET.SubElement(host_vuln, "results")
        
        # Host asset information
        host_asset = ET.SubElement(host_vuln, "hostAsset")
        ET.SubElement(host_asset, "id")
        ET.SubElement(host_asset, "dnsHostName")
        ET.SubElement(host_asset, "netbiosName")
        ET.SubElement(host_asset, "operatingSystem")
        ET.SubElement(host_asset, "lastVulnScan")
        
        return ET.tostring(root, encoding="utf-8")

    def search_vulnerable_hosts(self, cve_ids):
        """
        Search for hosts with specific CVE vulnerabilities
        Uses the hostinstancevuln endpoint for direct CVE search
        """
        if not cve_ids:
            return []
            
        url = f"{self.base_url}/qps/rest/2.0/search/am/hostinstancevuln"
        offset, page = 1, 1
        results = []

        while True:
            logger.info(f"Fetching vulnerable hosts page {page}, offset {offset}...")
            body = self.build_vuln_detection_request(cve_ids, offset)
            
            # Debug: Log the request
            logger.debug(f"Request URL: {url}")
            logger.debug(f"Request body: {body.decode('utf-8')}")
            
            resp = self.session.post(url, headers=self.qps_headers, auth=self.auth, data=body, verify=self.cert_path)
            
            if resp.status_code == 400:
                logger.error(f"Bad Request (400). Response: {resp.text}")
                raise Exception(f"Bad Request: {resp.text}")
            elif resp.status_code == 403:
                raise Exception("Forbidden. Check access/credentials for vulnerability detection API.")
            
            resp.raise_for_status()

            try:
                root = ET.fromstring(resp.content)
            except ET.ParseError:
                logger.error(f"XML Parse Error. Response content: {resp.content}")
                raise Exception("Malformed XML response from vulnerability search.")

            # Look for HostInstanceVuln elements
            vulns = root.findall(".//HostInstanceVuln")
            if not vulns:
                logger.info("No more vulnerability records found.")
                break

            results.extend(vulns)
            has_more = root.findtext(".//hasMoreRecords") == "true"
            if not has_more:
                break
            offset += self.page_size
            page += 1

        return results

    def extract_vulnerability_details(self, vuln_instances):
        """
        Extract vulnerability details from HostInstanceVuln elements
        Returns structured data about each vulnerable host
        """
        results = []
        
        for vuln in vuln_instances:
            # Extract vulnerability instance details
            host_instance_id = vuln.findtext("hostInstanceId", "")
            cve_id = vuln.findtext("cveId", "")
            qid = vuln.findtext("qid", "")
            status = vuln.findtext("status", "")
            severity = vuln.findtext("severity", "")
            first_found = vuln.findtext("firstFound", "")
            last_found = vuln.findtext("lastFound", "")
            port = vuln.findtext("port", "")
            protocol = vuln.findtext("protocol", "")
            results_text = vuln.findtext("results", "")
            
            # Extract host asset details
            host_asset = vuln.find("hostAsset")
            if host_asset is not None:
                host_id = host_asset.findtext("id", "")
                dns = host_asset.findtext("dnsHostName", "")
                netbios = host_asset.findtext("netbiosName", "")
                os_info = host_asset.findtext("operatingSystem", "")
                last_scan = host_asset.findtext("lastVulnScan", "")
            else:
                host_id = dns = netbios = os_info = last_scan = ""
            
            results.append({
                "Host ID": host_id,
                "Host Instance ID": host_instance_id,
                "DNS Name": dns,
                "NetBIOS Name": netbios,
                "Operating System": os_info,
                "CVE": cve_id,
                "QID": qid,
                "Severity": severity,
                "Status": status,
                "Port": port,
                "Protocol": protocol,
                "First Found": first_found,
                "Last Found": last_found,
                "Last Vulnerability Scan": last_scan,
                "Detection Results": results_text[:500] + "..." if len(results_text) > 500 else results_text
            })
        
        return results

    def get_host_list_detection(self, cve_ids):
        """
        Alternative method using Host List Detection API
        More direct for vulnerability-specific searches
        """
        url = f"{self.base_url}/api/2.0/fo/asset/host/vm/detection/"
        
        all_results = []
        
        for cve_id in cve_ids:
            logger.info(f"Searching for hosts vulnerable to {cve_id}...")
            
            params = {
                "action": "list",
                "cve_id": cve_id,
                "status": "Active",  # Only active vulnerabilities
                "show_results": "1",  # Include detection results
                "show_igs": "1",      # Include ignored/disabled status
                "max_days_since_detection": "365"  # Limit to detections in last year
            }
            
            try:
                resp = self.session.get(url, headers=self.fo_headers, params=params, verify=self.cert_path)
                resp.raise_for_status()
                
                root = ET.fromstring(resp.content)
                detections = root.findall(".//DETECTION")
                
                logger.info(f"Found {len(detections)} vulnerable hosts for {cve_id}")
                
                for detection in detections:
                    host_info = {
                        "CVE": cve_id,
                        "Host ID": detection.findtext("../IP", ""),  # Parent HOST element
                        "IP Address": detection.findtext("../IP", ""),
                        "DNS Name": detection.findtext("../DNS", ""),
                        "NetBIOS Name": detection.findtext("../NETBIOS", ""),
                        "Operating System": detection.findtext("../OS", ""),
                        "QID": detection.findtext("QID", ""),
                        "Vulnerability Title": detection.findtext("TITLE", ""),
                        "Severity": detection.findtext("SEVERITY", ""),
                        "Port": detection.findtext("PORT", ""),
                        "Protocol": detection.findtext("PROTOCOL", ""),
                        "First Found": detection.findtext("FIRST_FOUND_DATETIME", ""),
                        "Last Found": detection.findtext("LAST_FOUND_DATETIME", ""),
                        "Status": detection.findtext("STATUS", ""),
                        "Detection Results": detection.findtext("RESULTS", "")[:500] + "..." if detection.findtext("RESULTS", "") and len(detection.findtext("RESULTS", "")) > 500 else detection.findtext("RESULTS", "")
                    }
                    all_results.append(host_info)
                    
            except Exception as e:
                logger.error(f"Error searching for CVE {cve_id}: {str(e)}")
                continue
        
        return all_results

    def send_email(self, filename, cve_ids, vulnerable_count, total_detections):
        """Send email notification about vulnerable hosts"""
        if vulnerable_count > 0:
            outlook = win32.Dispatch("Outlook.Application")
            mail = outlook.CreateItem(0)
            
            cve_list = ", ".join(cve_ids)
            mail.Subject = f"[VULNERABILITY ALERT] {vulnerable_count} Vulnerable Hosts - CVE: {cve_list}"
            
            mail.Body = f"""
Hello,

Vulnerability scan results for CVE(s): {cve_list}

Summary:
- Total vulnerable hosts found: {vulnerable_count}
- Total vulnerability detections: {total_detections}

Please find attached the detailed vulnerability report.

IMMEDIATE ACTION REQUIRED:
- Review all affected systems
- Prioritize patching based on severity levels
- Verify patch deployment after remediation

Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Regards,
Vulnerability Management System
            """.strip()
            
            mail.Attachments.Add(os.path.abspath(filename))
            mail.Display()  # Opens the draft
            logger.info(f"Email draft created for {vulnerable_count} vulnerable hosts")
        else:
            logger.info("No vulnerable hosts found - email not created.")

    def run_cve_search(self, cve_ids):
        """
        Main method to search for vulnerable hosts by CVE
        Uses the hostinstancevuln endpoint for direct CVE search
        
        Args:
            cve_ids: List of CVE identifiers (e.g., ['CVE-2024-1234', 'CVE-2024-5678'])
        """
        self.login()
        try:
            logger.info(f"Searching for vulnerabilities using CVE(s): {', '.join(cve_ids)}")
            
            # Direct CVE search using hostinstancevuln endpoint
            vuln_instances = self.search_vulnerable_hosts(cve_ids)
            logger.info(f"Found {len(vuln_instances)} vulnerability instances")
            
            if not vuln_instances:
                logger.info("No vulnerable hosts found for the specified CVE(s).")
                # Create empty Excel file for tracking
                df_empty = pd.DataFrame(columns=[
                    "CVE", "Host ID", "Host Instance ID", "DNS Name", "NetBIOS Name", 
                    "Operating System", "QID", "Severity", "Port", "Protocol", 
                    "First Found", "Last Found", "Status", "Last Vulnerability Scan",
                    "Detection Results"
                ])
                filename = f"CVE_Vulnerability_Report_{'_'.join([c.replace('CVE-', '') for c in cve_ids])}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                df_empty.to_excel(filename, index=False)
                logger.info(f"Empty Excel file created: {filename}")
                return

            # Extract vulnerability details
            results = self.extract_vulnerability_details(vuln_instances)
            
            # Create DataFrame and sort by severity
            df = pd.DataFrame(results)
            
            # Sort by severity (5=Critical, 4=High, 3=Medium, 2=Low, 1=Info) then by Host ID
            severity_order = ["5", "4", "3", "2", "1"]  # Qualys severity levels
            if "Severity" in df.columns:
                df["Severity_Sort"] = pd.Categorical(df["Severity"], categories=severity_order, ordered=True)
                df = df.sort_values(by=["Severity_Sort", "Host ID", "CVE"])
                df = df.drop("Severity_Sort", axis=1)

            # Generate filename with timestamp
            filename = f"CVE_Vulnerability_Report_{'_'.join([c.replace('CVE-', '') for c in cve_ids])}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            
            # Save to Excel with formatting
            with pd.ExcelWriter(filename, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Vulnerability Details', index=False)
                
                # Create summary sheet
                summary_data = {
                    "Metric": [
                        "Total CVEs Searched",
                        "Total Vulnerable Hosts",
                        "Total Vulnerability Instances",
                        "Critical Severity (5)",
                        "High Severity (4)", 
                        "Medium Severity (3)",
                        "Low Severity (2)",
                        "Info Severity (1)",
                        "Search Date"
                    ],
                    "Value": [
                        len(cve_ids),
                        len(df["Host ID"].unique()) if not df.empty else 0,
                        len(df),
                        len(df[df["Severity"] == "5"]) if not df.empty else 0,
                        len(df[df["Severity"] == "4"]) if not df.empty else 0,
                        len(df[df["Severity"] == "3"]) if not df.empty else 0,
                        len(df[df["Severity"] == "2"]) if not df.empty else 0,
                        len(df[df["Severity"] == "1"]) if not df.empty else 0,
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    ]
                }
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name='Summary', index=False)

            vulnerable_hosts = len(df["Host ID"].unique()) if not df.empty else 0
            total_instances = len(df)
            
            logger.info(f"Vulnerability Search Results:")
            logger.info(f"    CVEs searched: {', '.join(cve_ids)}")
            logger.info(f"    Vulnerable hosts found: {vulnerable_hosts}")
            logger.info(f"    Total vulnerability instances: {total_instances}")
            if not df.empty:
                logger.info(f"    Severity breakdown:")
                for sev, label in [("5", "Critical"), ("4", "High"), ("3", "Medium"), ("2", "Low"), ("1", "Info")]:
                    count = len(df[df["Severity"] == sev])
                    if count > 0:
                        logger.info(f"        {label}: {count}")
            logger.info(f"Saved Excel report: {filename}")
            
            # Send email notification
            self.send_email(filename, cve_ids, vulnerable_hosts, total_instances)
            
        finally:
            self.logout()


def main():
    print("=== Qualys CVE-Based Vulnerability Scanner ===")
    print("Direct CVE to vulnerable hosts lookup")
    print("Enter CVE ID(s) to search for vulnerable systems\n")
    
    cve_input = input("Enter CVE ID(s) separated by commas: ").strip()
    if not cve_input:
        print("No CVE IDs provided.")
        sys.exit(1)

    # Parse and validate CVE IDs
    cve_ids = [cve.strip().upper() for cve in cve_input.split(",") if cve.strip()]
    valid_cves = []
    
    for cve in cve_ids:
        if cve.startswith("CVE-") and len(cve.split("-")) == 3:
            try:
                # Validate year and number parts
                parts = cve.split("-")
                year = int(parts[1])
                number = int(parts[2])
                if year >= 1999 and number >= 0:  # CVE program started in 1999
                    valid_cves.append(cve)
                else:
                    print(f"Warning: '{cve}' has invalid year or number")
            except ValueError:
                print(f"Warning: '{cve}' is not a valid CVE format")
        else:
            print(f
