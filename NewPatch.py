import requests
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
import pandas as pd
import logging
import sys
import os
import win32com.client as win32
from datetime import datetime
import json

# === CONFIGURATION ===
USERNAME = "your_qualys_username"
PASSWORD = "your_qualys_password"
CERT_PATH = "/path/to/your/corporate_cert.pem"  # Path to PEM bundle if needed, or set to False for testing
BASE_URL = "https://qualysapi.qg1.apps.qualys.in"  # Adjust to your region's API endpoint
PAGE_SIZE = 100  # If FO API supports pagination parameters; may not be used directly here
LOG_LEVEL = logging.INFO

# === LOGGER SETUP ===
logger = logging.getLogger("QualysCVESearcher")
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("[%(levelname)s] %(message)s")
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)
logger.setLevel(LOG_LEVEL)


class QualysCVESearcher:
    def __init__(self, username, password, cert_path, base_url=None):
        self.base_url = (base_url or BASE_URL).rstrip("/")
        self.session = requests.Session()
        self.auth = HTTPBasicAuth(username, password)
        # If certificate verification requires a custom bundle, set cert_path; else for testing you can set False
        self.cert_path = cert_path
        # Common headers
        self.fo_headers = {"X-Requested-With": "Python script"}
        self.qps_headers = {
            "Content-Type": "application/xml",
            "Accept": "application/xml"
        }

    def login(self):
        """Login to Qualys API via FO session API."""
        url = f"{self.base_url}/api/2.0/fo/session/"
        data = {
            "action": "login",
            "username": self.auth.username,
            "password": self.auth.password
        }
        logger.info("Logging in to Qualys API...")
        resp = self.session.post(url, headers=self.fo_headers, data=data, verify=self.cert_path)
        try:
            resp.raise_for_status()
        except Exception:
            logger.error(f"Login HTTP error: status {resp.status_code}, body: {resp.text}")
            raise
        # Confirm session cookie present
        if "QualysSession" not in self.session.cookies.get_dict():
            raise Exception("Login failed: QualysSession cookie not found.")
        logger.info("Login successful.")

    def logout(self):
        """Logout from Qualys API."""
        url = f"{self.base_url}/api/2.0/fo/session/"
        data = {"action": "logout"}
        try:
            self.session.post(url, headers=self.fo_headers, data=data, verify=self.cert_path)
        except Exception:
            pass
        logger.info("Logged out from Qualys API.")

    def get_host_list_detection(self, cve_ids, max_days_since_detection=365):
        """
        Use FO Host List Detection API to search hosts vulnerable to given CVEs.
        Returns a list of dicts with host + detection details.
        """
        url = f"{self.base_url}/api/2.0/fo/asset/host/vm/detection/"
        all_results = []

        for cve_id in cve_ids:
            logger.info(f"Searching for hosts vulnerable to {cve_id}...")
            params = {
                "action": "list",
                "cve_id": cve_id,
                "status": "Active",         # Only active vulnerabilities
                "show_results": "1",        # Include detection results
                "show_igs": "1",            # Include ignored/disabled status if present
                "max_days_since_detection": str(max_days_since_detection)
            }
            try:
                resp = self.session.get(url, headers=self.fo_headers, params=params, verify=self.cert_path)
                resp.raise_for_status()
            except Exception as e:
                logger.error(f"Error fetching detections for {cve_id}: {str(e)}; response: {getattr(e, 'response', None)}")
                continue

            # Parse XML
            try:
                root = ET.fromstring(resp.content)
            except ET.ParseError:
                logger.error(f"Failed to parse XML for CVE {cve_id}. Raw response:\n{resp.text}")
                continue

            # The typical structure:
            # <HOST_LIST>
            #   <HOST>
            #     <ID>...</ID>
            #     <IP>...</IP>
            #     <DNS>...</DNS>
            #     <NETBIOS>...</NETBIOS>
            #     <OS>...</OS>
            #     <VULN_DETECTION_LIST>
            #       <DETECTION> ... </DETECTION>
            #       ...
            #     </VULN_DETECTION_LIST>
            #   </HOST>
            #   ...
            # </HOST_LIST>
            #
            # But the exact tag names can vary; we search generically for HOST elements.
            hosts = root.findall(".//HOST")
            logger.info(f"Found {len(hosts)} HOST entries in response for {cve_id}")

            for host in hosts:
                host_ip = host.findtext("IP", "")
                host_dns = host.findtext("DNS", "")
                host_netbios = host.findtext("NETBIOS", "")
                host_os = host.findtext("OS", "")
                host_id = host.findtext("ID", "")  # sometimes HOST ID may be under <ID>

                # Search DETECTION elements under this HOST
                detections = host.findall(".//DETECTION")
                if not detections:
                    # In some responses, detection may be nested differently or absent
                    logger.debug(f"No DETECTION found under HOST {host_ip} for CVE {cve_id}")
                    continue

                for det in detections:
                    # Extract fields from DETECTION element
                    det_qid = det.findtext("QID", "")
                    det_title = det.findtext("TITLE", "")
                    det_severity = det.findtext("SEVERITY", "")
                    det_port = det.findtext("PORT", "")
                    det_protocol = det.findtext("PROTOCOL", "")
                    det_first = det.findtext("FIRST_FOUND_DATETIME", "") or det.findtext("FIRST_FOUND", "")
                    det_last = det.findtext("LAST_FOUND_DATETIME", "") or det.findtext("LAST_FOUND", "")
                    det_status = det.findtext("STATUS", "")
                    det_results = det.findtext("RESULTS", "") or ""
                    # Truncate long results text for summary columns
                    det_results_summary = det_results[:500] + "..." if len(det_results) > 500 else det_results

                    entry = {
                        "CVE": cve_id,
                        "Host ID": host_id,
                        "IP Address": host_ip,
                        "DNS Name": host_dns,
                        "NetBIOS Name": host_netbios,
                        "Operating System": host_os,
                        "QID": det_qid,
                        "Vulnerability Title": det_title,
                        "Severity": det_severity,
                        "Port": det_port,
                        "Protocol": det_protocol,
                        "First Found": det_first,
                        "Last Found": det_last,
                        "Status": det_status,
                        "Detection Results": det_results_summary
                    }
                    all_results.append(entry)

            logger.info(f"Total vulnerable host entries collected for {cve_id}: {len(all_results)}")

        return all_results

    def send_email(self, filename, cve_ids, vulnerable_count, total_detections):
        """
        Draft an Outlook email with the report attached if vulnerabilities found.
        Opens the draft for review/send.
        """
        if vulnerable_count > 0:
            try:
                outlook = win32.Dispatch("Outlook.Application")
            except Exception as e:
                logger.error(f"Failed to dispatch Outlook.Application: {e}")
                return

            mail = outlook.CreateItem(0)  # 0=MailItem
            cve_list_str = ", ".join(cve_ids)
            mail.Subject = f"[VULNERABILITY ALERT] {vulnerable_count} Vulnerable Hosts - CVE(s): {cve_list_str}"
            body = f"""
Hello,

Vulnerability scan results for CVE(s): {cve_list_str}

Summary:
- Total vulnerable hosts found: {vulnerable_count}
- Total vulnerability instances: {total_detections}

Please find attached the detailed vulnerability report.

IMMEDIATE ACTION REQUIRED:
- Review all affected systems
- Prioritize patching based on severity levels
- Verify patch deployment after remediation

Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Regards,
Vulnerability Management System
""".strip()
            mail.Body = body
            try:
                abs_path = os.path.abspath(filename)
                mail.Attachments.Add(abs_path)
            except Exception as e:
                logger.error(f"Failed to attach file {filename}: {e}")
            # Display draft for user to review/send
            mail.Display()
            logger.info(f"Email draft created for {vulnerable_count} vulnerable hosts.")
        else:
            logger.info("No vulnerable hosts found - no email drafted.")

    def run_cve_search(self, cve_ids):
        """
        Main method: login, search hosts by CVE, generate Excel report, draft email if needed, logout.
        """
        if not cve_ids:
            logger.error("No CVE IDs provided to run_cve_search.")
            return

        # Login
        self.login()
        try:
            # Directly fetch host detections by CVE
            results_list = self.get_host_list_detection(cve_ids)
            if not results_list:
                logger.info("No vulnerable hosts found for the specified CVE(s). Creating an empty report.")
                # Create empty DataFrame with expected columns
                columns = [
                    "CVE", "Host ID", "IP Address", "DNS Name", "NetBIOS Name",
                    "Operating System", "QID", "Vulnerability Title", "Severity",
                    "Port", "Protocol", "First Found", "Last Found", "Status",
                    "Detection Results"
                ]
                df_empty = pd.DataFrame(columns=columns)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"CVE_Vulnerability_Report_{'_'.join([c.replace('CVE-', '') for c in cve_ids])}_{timestamp}.xlsx"
                df_empty.to_excel(filename, index=False)
                logger.info(f"Empty Excel file created: {filename}")
                # No email since no vulnerabilities
                return

            # Build DataFrame
            df = pd.DataFrame(results_list)

            # Sort by severity if present: Qualys returns severity numeric as string "5","4",...
            if "Severity" in df.columns:
                # Define ordering: Critical=5, High=4, etc.
                severity_order = ["5", "4", "3", "2", "1"]
                df["Severity_Sort"] = pd.Categorical(df["Severity"], categories=severity_order, ordered=True)
                # Sort by Severity, then Host ID, then CVE
                sort_cols = ["Severity_Sort"]
                if "Host ID" in df.columns:
                    sort_cols.append("Host ID")
                if "CVE" in df.columns:
                    sort_cols.append("CVE")
                df = df.sort_values(by=sort_cols)
                df = df.drop(columns=["Severity_Sort"], errors='ignore')

            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"CVE_Vulnerability_Report_{'_'.join([c.replace('CVE-', '') for c in cve_ids])}_{timestamp}.xlsx"

            # Save to Excel with multiple sheets: Details and Summary
            with pd.ExcelWriter(filename, engine='openpyxl') as writer:
                # Details sheet
                df.to_excel(writer, sheet_name='Vulnerability Details', index=False)

                # Summary sheet
                unique_hosts = df["Host ID"].nunique() if "Host ID" in df.columns else 0
                total_instances = len(df)
                # Count by severity
                summary_data = {
                    "Metric": [
                        "Total CVEs Searched",
                        "Total Vulnerability Instances",
                        "Total Vulnerable Hosts",
                        "Critical Severity (5)",
                        "High Severity (4)",
                        "Medium Severity (3)",
                        "Low Severity (2)",
                        "Info Severity (1)",
                        "Search Date"
                    ],
                    "Value": [
                        len(cve_ids),
                        total_instances,
                        unique_hosts,
                        int(df[df["Severity"] == "5"].shape[0]) if "Severity" in df.columns else 0,
                        int(df[df["Severity"] == "4"].shape[0]) if "Severity" in df.columns else 0,
                        int(df[df["Severity"] == "3"].shape[0]) if "Severity" in df.columns else 0,
                        int(df[df["Severity"] == "2"].shape[0]) if "Severity" in df.columns else 0,
                        int(df[df["Severity"] == "1"].shape[0]) if "Severity" in df.columns else 0,
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    ]
                }
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name='Summary', index=False)

                # CVE list sheet
                cve_list_df = pd.DataFrame({"CVE": cve_ids})
                cve_list_df.to_excel(writer, sheet_name='CVE List', index=False)

            logger.info(f"Saved Excel report: {filename}")

            # Draft email if vulnerabilities found
            vulnerable_hosts_count = unique_hosts
            self.send_email(filename, cve_ids, vulnerable_hosts_count, total_instances)

        finally:
            # Ensure logout even on error
            try:
                self.logout()
            except Exception as e:
                logger.warning(f"Error during logout: {e}")


if __name__ == "__main__":
    # Example usage:
    # Read CVE IDs from command-line arguments or a JSON file, etc.
    # For demonstration, we pick some CVEs:
    import argparse

    parser = argparse.ArgumentParser(description="Qualys CVE Vulnerability Searcher")
    parser.add_argument("--cves", nargs="+", required=True,
                        help="List of CVE IDs to search, e.g. CVE-2024-1234 CVE-2024-5678")
    parser.add_argument("--username", default=USERNAME, help="Qualys username")
    parser.add_argument("--password", default=PASSWORD, help="Qualys password")
    parser.add_argument("--cert", default=CERT_PATH, help="Path to corporate cert PEM or False")
    parser.add_argument("--base-url", default=BASE_URL, help="Qualys API base URL")
    args = parser.parse_args()

    # Optionally override via env or args
    searcher = QualysCVESearcher(
        username=args.username,
        password=args.password,
        cert_path=(False if str(args.cert).lower() in ("false","none","") else args.cert),
        base_url=args.base_url
    )
    try:
        searcher.run_cve_search(args.cves)
    except Exception as e:
        logger.error(f"Exception during CVE search: {e}")
        sys.exit(1)
