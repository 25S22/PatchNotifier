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

    def build_host_detection_request(self, qids, offset):
        """
        Build XML request for host detection search using QIDs
        Uses the more efficient host detection endpoint
        """
        root = ET.Element("ServiceRequest")
        filters = ET.SubElement(root, "filters")
        
        # Create QID filter - can search multiple QIDs at once
        qid_list = ",".join([str(q["qid"]) for q in qids])
        ET.SubElement(filters, "Criteria", field="qid", operator="IN").text = qid_list
        
        # Only show active vulnerabilities (not fixed)
        ET.SubElement(filters, "Criteria", field="status", operator="EQUALS").text = "Active"
        
        prefs = ET.SubElement(root, "preferences")
        ET.SubElement(prefs, "startFromOffset").text = str(offset)
        ET.SubElement(prefs, "limitResults").text = str(self.page_size)
        
        # Request specific fields we need
        fields = ET.SubElement(root, "fields")
        host = ET.SubElement(fields, "HostAsset")
        ET.SubElement(host, "id")
        ET.SubElement(host, "dnsHostName")
        ET.SubElement(host, "netbiosName")
        ET.SubElement(host, "operatingSystem")
        ET.SubElement(host, "lastVulnScan")
        
        # Include detection details
        detection_list = ET.SubElement(host, "HostAssetVulnDetectionList")
        detection = ET.SubElement(detection_list, "HostAssetVulnDetection")
        ET.SubElement(detection, "qid")
        ET.SubElement(detection, "status")
        ET.SubElement(detection, "firstFound")
        ET.SubElement(detection, "lastFound")
        ET.SubElement(detection, "severity")
        ET.SubElement(detection, "port")
        ET.SubElement(detection, "protocol")
        ET.SubElement(detection, "results")
        
        return ET.tostring(root, encoding="utf-8")

    def search_vulnerable_hosts(self, qids):
        """
        Search for hosts with specific vulnerability QIDs
        This is much more efficient than filtering software installations
        """
        if not qids:
            return []
            
        url = f"{self.base_url}/qps/rest/2.0/search/am/hostasset"
        offset, page = 1, 1
        results = []

        while True:
            logger.info(f"Fetching vulnerable hosts page {page}, offset {offset}...")
            body = self.build_host_detection_request(qids, offset)
            resp = self.session.post(url, headers=self.qps_headers, auth=self.auth, data=body, verify=self.cert_path)
            
            if resp.status_code == 403:
                raise Exception("Forbidden. Check access/credentials for vulnerability detection API.")
            resp.raise_for_status()

            try:
                root = ET.fromstring(resp.content)
            except ET.ParseError:
                raise Exception("Malformed XML response from host detection search.")

            assets = root.findall(".//HostAsset")
            if not assets:
                break

            results.extend(assets)
            has_more = root.findtext(".//hasMoreRecords") == "true"
            if not has_more:
                break
            offset += self.page_size
            page += 1

        return results

    def extract_vulnerability_details(self, hosts, qids):
        """
        Extract vulnerability details from host assets
        Returns structured data about each vulnerable host
        """
        results = []
        qid_lookup = {q["qid"]: q for q in qids}
        
        for host in hosts:
            host_id = host.findtext("id", "")
            dns = host.findtext("dnsHostName", "")
            netbios = host.findtext("netbiosName", "")
            os_info = host.findtext("operatingSystem", "")
            last_scan = host.findtext("lastVulnScan", "")
            
            # Extract vulnerability detections
            detections = host.findall(".//HostAssetVulnDetection")
            
            for detection in detections:
                qid = detection.findtext("qid", "")
                status = detection.findtext("status", "")
                first_found = detection.findtext("firstFound", "")
                last_found = detection.findtext("lastFound", "")
                severity = detection.findtext("severity", "")
                port = detection.findtext("port", "")
                protocol = detection.findtext("protocol", "")
                results_text = detection.findtext("results", "")
                
                # Get CVE and vulnerability title from our QID lookup
                vuln_info = qid_lookup.get(qid, {})
                cve = vuln_info.get("cve", "")
                title = vuln_info.get("title", "")
                
                results.append({
                    "Host ID": host_id,
                    "DNS Name": dns,
                    "NetBIOS Name": netbios,
                    "Operating System": os_info,
                    "CVE": cve,
                    "QID": qid,
                    "Vulnerability Title": title,
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

    def run_cve_search(self, cve_ids, use_detection_api=True):
        """
        Main method to search for vulnerable hosts by CVE
        
        Args:
            cve_ids: List of CVE identifiers (e.g., ['CVE-2024-1234', 'CVE-2024-5678'])
            use_detection_api: If True, use Host List Detection API (recommended)
                              If False, use Asset Search API with QID lookup
        """
        self.login()
        try:
            if use_detection_api:
                # Method 1: Direct CVE search using Host List Detection API (Recommended)
                results = self.get_host_list_detection(cve_ids)
            else:
                # Method 2: QID lookup + Asset Search API
                all_qids = []
                for cve_id in cve_ids:
                    qids = self.get_qid_from_cve(cve_id)
                    all_qids.extend(qids)
                
                if not all_qids:
                    logger.error("No QIDs found for the provided CVEs")
                    return
                
                hosts = self.search_vulnerable_hosts(all_qids)
                results = self.extract_vulnerability_details(hosts, all_qids)
            
            if not results:
                logger.info("No vulnerable hosts found for the specified CVE(s).")
                # Create empty Excel file for tracking
                df_empty = pd.DataFrame(columns=[
                    "CVE", "Host ID", "IP Address", "DNS Name", "NetBIOS Name", 
                    "Operating System", "QID", "Vulnerability Title", "Severity",
                    "Port", "Protocol", "First Found", "Last Found", "Status",
                    "Detection Results"
                ])
                filename = f"CVE_Vulnerability_Report_{'_'.join([c.replace('CVE-', '') for c in cve_ids])}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                df_empty.to_excel(filename, index=False)
                logger.info(f"Empty Excel file created: {filename}")
                return

            # Create DataFrame and sort by severity
            df = pd.DataFrame(results)
            
            # Sort by severity (Critical, High, Medium, Low) then by Host ID
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
                        "Total Vulnerability Detections",
                        "Critical Severity",
                        "High Severity", 
                        "Medium Severity",
                        "Low Severity",
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
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    ]
                }
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name='Summary', index=False)

            vulnerable_hosts = len(df["Host ID"].unique()) if not df.empty else 0
            total_detections = len(df)
            
            logger.info(f"Vulnerability Search Results:")
            logger.info(f"    CVEs searched: {', '.join(cve_ids)}")
            logger.info(f"    Vulnerable hosts found: {vulnerable_hosts}")
            logger.info(f"    Total vulnerability detections: {total_detections}")
            logger.info(f"Saved Excel report: {filename}")
            
            # Send email notification
            self.send_email(filename, cve_ids, vulnerable_hosts, total_detections)
            
        finally:
            self.logout()


def main():
    print("=== Qualys CVE-Based Vulnerability Scanner ===")
    print("This tool searches for hosts vulnerable to specific CVEs")
    print("Much more accurate than software name filtering!\n")
    
    cve_input = input("Enter CVE ID(s) separated by commas (e.g., CVE-2024-1234,CVE-2024-5678): ").strip()
    if not cve_input:
        print("No CVE IDs provided.")
        sys.exit(1)

    # Parse and validate CVE IDs
    cve_ids = [cve.strip().upper() for cve in cve_input.split(",") if cve.strip()]
    valid_cves = []
    
    for cve in cve_ids:
        if cve.startswith("CVE-") and len(cve.split("-")) == 3:
            valid_cves.append(cve)
        else:
            print(f"Warning: '{cve}' is not a valid CVE format (should be CVE-YYYY-NNNN)")
    
    if not valid_cves:
        print("No valid CVE IDs provided.")
        sys.exit(1)
    
    print(f"Searching for vulnerabilities: {', '.join(valid_cves)}")
    
    # Ask which method to use
    method = input("\nUse direct CVE detection API? (y/n) [recommended: y]: ").strip().lower()
    use_detection_api = method != 'n'
    
    if use_detection_api:
        print("Using Host List Detection API (direct CVE search)")
    else:
        print("Using Asset Search API with QID lookup")

    qs = QualysCVESearcher(USERNAME, PASSWORD, CERT_PATH, page_size=PAGE_SIZE)
    qs.run_cve_search(valid_cves, use_detection_api)


if __name__ == "__main__":
    main()
