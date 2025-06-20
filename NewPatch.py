import requests
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
import pandas as pd
import logging
import sys
import os
import win32com.client as win32
from datetime import datetime
import getpass

# === DEFAULT CONFIGURATION ===
# Set your defaults here. If left as None (or False for cert), the script will prompt.
DEFAULT_USERNAME = None            # e.g., "your_qualys_username"
DEFAULT_PASSWORD = None            # e.g., "your_qualys_password"
DEFAULT_CERT_PATH = None           # e.g., "/path/to/your/corporate_cert.pem"; set False to skip verification
DEFAULT_BASE_URL = None            # e.g., "https://qualysapi.qg1.apps.qualys.in"
DEFAULT_PAGE_SIZE = 100            # e.g., 100
DEFAULT_LOG_LEVEL = "INFO"         # e.g., "DEBUG", "INFO", "WARNING", "ERROR"

# === LOGGER SETUP ===
logger = logging.getLogger("QualysCVESearcher")
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("[%(levelname)s] %(message)s")
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)
# Set log level from default or fallback to INFO
level_name = DEFAULT_LOG_LEVEL if DEFAULT_LOG_LEVEL else "INFO"
logger.setLevel(getattr(logging, level_name.upper(), logging.INFO))


class QualysCVESearcher:
    def __init__(self, username, password, cert_path, base_url, page_size=100):
        """
        username, password: Qualys credentials
        cert_path: path to corporate CA bundle PEM, or False to skip verification
        base_url: e.g. "https://qualysapi.qg1.apps.qualys.in"
        page_size: used in search_vulnerable_hosts pagination
        """
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.auth = HTTPBasicAuth(username, password)
        self.cert_path = cert_path
        self.page_size = page_size
        # headers
        self.fo_headers = {"X-Requested-With": "Python script"}
        self.qps_headers = {
            "Content-Type": "application/xml",
            "Accept": "application/xml"
        }

    def login(self):
        """Login to Qualys API and establish session (FO session)."""
        url = f"{self.base_url}/api/2.0/fo/session/"
        data = {
            "action": "login",
            "username": self.auth.username,
            "password": self.auth.password
        }
        logger.info("Logging in...")
        resp = self.session.post(url, headers=self.fo_headers, data=data, verify=self.cert_path)
        try:
            resp.raise_for_status()
        except Exception:
            logger.error(f"Login HTTP error: status {resp.status_code}, body: {resp.text}")
            raise
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
        logger.info("Logged out.")

    def get_qid_from_cve(self, cve_id):
        """
        Get Qualys QID(s) associated with a CVE using FO Knowledge Base API.
        May raise on bad request; logs response text for diagnosis.
        """
        url = f"{self.base_url}/api/2.0/fo/knowledge_base/vuln/"
        params = {
            "action": "list",
            "details": "All",
            "cve_id": cve_id
        }
        logger.info(f"Looking up QID for CVE: {cve_id}")
        try:
            resp = self.session.get(url, headers=self.fo_headers, params=params, verify=self.cert_path)
        except Exception as e:
            logger.error(f"HTTP request failed for CVE→QID lookup: {e}")
            raise
        if resp.status_code != 200:
            logger.error(f"Bad response for CVE→QID lookup: status {resp.status_code}, body: {resp.text}")
            raise Exception(f"CVE→QID lookup returned {resp.status_code}")
        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError:
            logger.error(f"Malformed XML response when looking up QID for {cve_id}. Body:\n{resp.text}")
            raise Exception("Malformed XML in CVE→QID lookup.")

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
            logger.info(f"Found QIDs for {cve_id}: {[q['qid'] for q in qids]}")
        return qids

    def build_vuln_detection_request(self, qids, offset):
        """
        Build XML request for vulnerability detection search using QIDs
        Uses QPS REST API endpoint /qps/rest/2.0/search/am/hostinstancevuln
        """
        root = ET.Element("ServiceRequest")
        filters = ET.SubElement(root, "filters")
        # QID filter
        if len(qids) == 1:
            ET.SubElement(filters, "Criteria", field="qid", operator="EQUALS").text = str(qids[0])
        else:
            qid_list = ",".join([str(qid) for qid in qids])
            ET.SubElement(filters, "Criteria", field="qid", operator="IN").text = qid_list
        # Only active
        ET.SubElement(filters, "Criteria", field="status", operator="EQUALS").text = "Active"
        # Pagination preferences
        prefs = ET.SubElement(root, "preferences")
        ET.SubElement(prefs, "startFromOffset").text = str(offset)
        ET.SubElement(prefs, "limitResults").text = str(self.page_size)
        # Fields to request
        fields = ET.SubElement(root, "fields")
        host_vuln = ET.SubElement(fields, "HostInstanceVuln")
        for tag in [
            "hostInstanceId", "cveId", "qid", "status", "severity",
            "firstFound", "lastFound", "port", "protocol", "results"
        ]:
            ET.SubElement(host_vuln, tag)
        # Host asset block
        host_asset = ET.SubElement(host_vuln, "hostAsset")
        for tag in ["id", "dnsHostName", "netbiosName", "operatingSystem", "lastVulnScan"]:
            ET.SubElement(host_asset, tag)
        return ET.tostring(root, encoding="utf-8")

    def search_vulnerable_hosts(self, qids):
        """
        Search for hosts with specific QID vulnerabilities via QPS REST API.
        Uses pagination with self.page_size.
        Returns a list of XML Element <HostInstanceVuln> elements.
        """
        if not qids:
            return []
        url = f"{self.base_url}/qps/rest/2.0/search/am/hostinstancevuln"
        offset, page = 1, 1
        results = []
        while True:
            logger.info(f"Fetching vulnerable hosts page {page}, offset {offset}...")
            body = self.build_vuln_detection_request(qids, offset)
            logger.debug(f"Request body: {body.decode('utf-8')}")
            try:
                resp = self.session.post(url, headers=self.qps_headers, auth=self.auth,
                                         data=body, verify=self.cert_path)
            except Exception as e:
                logger.error(f"HTTP error during hostinstancevuln search: {e}")
                raise
            if resp.status_code == 400:
                logger.error(f"Bad Request (400) on hostinstancevuln search. Body:\n{resp.text}")
                raise Exception(f"Bad Request: {resp.text}")
            elif resp.status_code == 403:
                raise Exception("Forbidden. Check access/credentials for vulnerability detection API.")
            try:
                resp.raise_for_status()
            except Exception:
                logger.error(f"Error response on hostinstancevuln: status {resp.status_code}, body: {resp.text}")
                raise

            try:
                root = ET.fromstring(resp.content)
            except ET.ParseError:
                logger.error(f"Malformed XML from hostinstancevuln search. Raw:\n{resp.text}")
                raise Exception("Malformed XML in vulnerability search.")

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
        Extract vulnerability details from HostInstanceVuln elements.
        Returns list of dicts for DataFrame.
        """
        results = []
        for vuln in vuln_instances:
            host_instance_id = vuln.findtext("hostInstanceId", "")
            cve_id = vuln.findtext("cveId", "")
            qid = vuln.findtext("qid", "")
            status = vuln.findtext("status", "")
            severity = vuln.findtext("severity", "")
            first_found = vuln.findtext("firstFound", "")
            last_found = vuln.findtext("lastFound", "")
            port = vuln.findtext("port", "")
            protocol = vuln.findtext("protocol", "")
            results_text = vuln.findtext("results", "") or ""
            results_summary = results_text[:500] + "..." if len(results_text) > 500 else results_text

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
                "Detection Results": results_summary
            })
        return results

    def get_host_list_detection(self, cve_ids, max_days_since_detection=365):
        """
        Alternative FO Host List Detection API: direct CVE search bypassing QID mapping.
        Returns a list of dicts similar to extract_vulnerability_details output, but fields may differ.
        """
        url = f"{self.base_url}/api/2.0/fo/asset/host/vm/detection/"
        all_results = []
        for cve_id in cve_ids:
            cve_id = cve_id.strip()
            if not cve_id:
                continue
            logger.info(f"Searching for hosts vulnerable to {cve_id} (Host List Detection API)...")
            params = {
                "action": "list",
                "cve_id": cve_id,
                "status": "Active",
                "show_results": "1",
                "show_igs": "1",
                "max_days_since_detection": str(max_days_since_detection)
            }
            try:
                resp = self.session.get(url, headers=self.fo_headers, params=params, verify=self.cert_path)
                resp.raise_for_status()
            except Exception as e:
                logger.error(f"Error fetching Host List Detection for {cve_id}: {e}")
                continue

            try:
                root = ET.fromstring(resp.content)
            except ET.ParseError:
                logger.error(f"Malformed XML in Host List Detection for {cve_id}. Raw:\n{resp.text}")
                continue

            hosts = root.findall(".//HOST")
            logger.info(f"Found {len(hosts)} HOST entries for CVE {cve_id}")
            for host in hosts:
                host_id = host.findtext("ID", "")
                host_ip = host.findtext("IP", "")
                host_dns = host.findtext("DNS", "")
                host_netbios = host.findtext("NETBIOS", "")
                host_os = host.findtext("OS", "")
                detections = host.findall(".//DETECTION")
                if not detections:
                    continue
                for det in detections:
                    det_qid = det.findtext("QID", "")
                    det_title = det.findtext("TITLE", "")
                    det_severity = det.findtext("SEVERITY", "")
                    det_port = det.findtext("PORT", "")
                    det_protocol = det.findtext("PROTOCOL", "")
                    det_first = det.findtext("FIRST_FOUND_DATETIME", "") or det.findtext("FIRST_FOUND", "")
                    det_last = det.findtext("LAST_FOUND_DATETIME", "") or det.findtext("LAST_FOUND", "")
                    det_status = det.findtext("STATUS", "")
                    det_results = det.findtext("RESULTS", "") or ""
                    det_results_summary = det_results[:500] + "..." if len(det_results) > 500 else det_results

                    entry = {
                        "Host ID": host_id,
                        "Host Instance ID": "",  # Not provided by FO CVE search directly
                        "DNS Name": host_dns,
                        "NetBIOS Name": host_netbios,
                        "Operating System": host_os,
                        "CVE": cve_id,
                        "QID": det_qid,
                        "Severity": det_severity,
                        "Status": det_status,
                        "Port": det_port,
                        "Protocol": det_protocol,
                        "First Found": det_first,
                        "Last Found": det_last,
                        "Last Vulnerability Scan": "",
                        "Detection Results": det_results_summary
                    }
                    all_results.append(entry)
            logger.info(f"Collected {len(all_results)} total entries so far (including previous CVEs).")
        return all_results

    def send_email(self, filename, cve_ids, vulnerable_count, total_detections):
        """
        Send email notification via Outlook draft.
        """
        if vulnerable_count > 0:
            try:
                outlook = win32.Dispatch("Outlook.Application")
            except Exception as e:
                logger.error(f"Failed to dispatch Outlook.Application: {e}")
                return
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
            try:
                abs_path = os.path.abspath(filename)
                mail.Attachments.Add(abs_path)
            except Exception as e:
                logger.error(f"Failed to attach file {filename}: {e}")
            mail.Display()
            logger.info(f"Email draft created for {vulnerable_count} vulnerable hosts.")
        else:
            logger.info("No vulnerable hosts found - no email drafted.")

    def run_cve_search(self, cve_ids, use_qid_lookup=True):
        """
        Main: login, then either QID-based search or direct CVE search (fallback or per user choice),
        generate Excel, send email, logout.
        use_qid_lookup: if True, attempt get_qid_from_cve + search_vulnerable_hosts; if that fails or empty, fallback to direct CVE search.
        """
        if not cve_ids:
            logger.error("No CVE IDs provided.")
            return

        self.login()
        try:
            results = []
            if use_qid_lookup:
                # Attempt QID-based search
                all_qids = []
                cve_to_qid_mapping = {}
                for cve in cve_ids:
                    try:
                        qid_info = self.get_qid_from_cve(cve)
                    except Exception as e:
                        logger.warning(f"QID lookup failed for {cve}: {e}")
                        qid_info = []
                    if qid_info:
                        qids_for_cve = [info["qid"] for info in qid_info]
                        all_qids.extend(qids_for_cve)
                        cve_to_qid_mapping[cve] = qids_for_cve
                    else:
                        logger.warning(f"No QIDs found for CVE {cve}, skipping in QID-based step.")
                if all_qids:
                    # Perform hostinstancevuln search
                    try:
                        vuln_instances = self.search_vulnerable_hosts(all_qids)
                        logger.info(f"Found {len(vuln_instances)} vulnerability instances via QID-based search.")
                        results = self.extract_vulnerability_details(vuln_instances)
                    except Exception as e:
                        logger.error(f"Error during QID-based host search: {e}")
                        results = []
                else:
                    logger.info("No QIDs found for any CVE; skipping QID-based search.")
            # If no results from QID-based or use_qid_lookup=False, fallback to direct CVE search
            if not results:
                logger.info("Performing direct CVE search via Host List Detection API...")
                results = self.get_host_list_detection(cve_ids)
                logger.info(f"Direct CVE search returned {len(results)} entries.")

            # If still no results, create empty report
            if not results:
                logger.info("No vulnerable hosts found. Creating empty report.")
                columns = [
                    "Host ID", "Host Instance ID", "DNS Name", "NetBIOS Name", "Operating System",
                    "CVE", "QID", "Severity", "Status", "Port", "Protocol",
                    "First Found", "Last Found", "Last Vulnerability Scan", "Detection Results"
                ]
                df_empty = pd.DataFrame(columns=columns)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                fname = f"CVE_Vulnerability_Report_{'_'.join([c.replace('CVE-', '') for c in cve_ids])}_{timestamp}.xlsx"
                df_empty.to_excel(fname, index=False)
                logger.info(f"Empty Excel file created: {fname}")
                return

            # Build DataFrame
            df = pd.DataFrame(results)
            # Sort by severity if present
            if "Severity" in df.columns:
                severity_order = ["5", "4", "3", "2", "1"]
                df["Severity_Sort"] = pd.Categorical(df["Severity"], categories=severity_order, ordered=True)
                sort_cols = ["Severity_Sort"]
                if "Host ID" in df.columns:
                    sort_cols.append("Host ID")
                if "CVE" in df.columns:
                    sort_cols.append("CVE")
                df = df.sort_values(by=sort_cols)
                df = df.drop(columns=["Severitint(df[df["Severity"] == "5"].shape[0]) if "Severity" in df.columns else 0,
                        int(df[df["Severity"] == "4"].shape[0]) if "Severity" in df.columns else 0,
                        int(df[df["Severity"] == "3"].shape[0]) if "Severity" in df.columns else 0,
                        int(df[df["Severity"] == "2"].shape[0]) if "Severity" in df.columns else 0,
                        int(df[df["Severity"] == "1"].shape[0]) if "Severity" in df.columns else 0,
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    ]
                }
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name="Summary", index=False)
                # CVE to QID mapping sheet (if QID-based did yield something)
                mapping = []
                if use_qid_lookup:
                    for row in results:
                        cve = row.get("CVE", "")
                        qid = row.get("QID", "")
                        if cve and qid:
                            mapping.append({"CVE": cve, "QID": qid})
                if mapping:
                    mapping_df = pd.DataFrame(mapping).drop_duplicates()
                    mapping_df.to_excel(writer, sheet_name="CVE to QID Mapping", index=False)
                # CVE List sheet
                cve_list_df = pd.DataFrame({"CVE": cve_ids})
                cve_list_df.to_excel(writer, sheet_name="CVE List", index=False)
            logger.info(f"Saved Excel report: {fname}")

            # Send email draft if any vulnerabilities
            unique_hosts = df["Host ID"].nunique() if "Host ID" in df.columns else 0
            self.send_email(fname, cve_ids, unique_hosts, len(df))

        finally:
            try:
                self.logout()
            except Exception as e:
                logger.warning(f"Error during logout: {e}")


def prompt_non_empty(prompt_text, default=None, is_password=False):
    """
    Prompt user until a non-empty response (or default if provided).
    """
    while True:
        if default is not None:
            # Use default without prompting for value
            if is_password:
                # do not print default password
                return default
            else:
                print(f"{prompt_text} [Using default: {default}]")
                return default
        # No default: prompt user
        if is_password:
            val = getpass.getpass(prompt_text + ": ")
        else:
            val = input(prompt_text + ": ").strip()
        if val:
            return val
        print("Input cannot be empty.")


if __name__ == "__main__":
    print("=== Qualys CVE Vulnerability Searcher (Interactive with Defaults) ===")

    # 1. Base URL
    if DEFAULT_BASE_URL:
        base_url = DEFAULT_BASE_URL
        print(f"Using default Base URL: {base_url}")
    else:
        base_url = input("Enter Qualys API Base URL (e.g., https://qualysapi.qg1.apps.qualys.in): ").strip()
        while not base_url:
            print("Base URL is required.")
            base_url = input("Enter Qualys API Base URL: ").strip()

    # 2. Username
    username = prompt_non_empty("Enter Qualys username", default=DEFAULT_USERNAME)

    # 3. Password
    password = prompt_non_empty("Enter Qualys password", default=DEFAULT_PASSWORD, is_password=True)

    # 4. Cert path or skip
    if DEFAULT_CERT_PATH is not None:
        cert_path = DEFAULT_CERT_PATH
        if cert_path:
            print(f"Using default certificate path: {cert_path}")
        else:
            print("Default: SSL verification is skipped (verify=False).")
    else:
        cert_input = input("Enter path to corporate cert PEM (leave blank to skip SSL verification): ").strip()
        if cert_input:
            cert_path = cert_input
        else:
            cert_path = False
            print("SSL verification will be skipped (verify=False).")

    # 5. Page size
    if DEFAULT_PAGE_SIZE:
        page_size = DEFAULT_PAGE_SIZE
        print(f"Using default page size: {page_size}")
    else:
        while True:
            ps = input("Enter page size (number of results per page for QID-based search, e.g., 100): ").strip()
            if not ps:
                print("Page size is required.")
                continue
            try:
                page_size = int(ps)
                if page_size <= 0:
                    raise ValueError
                break
            except ValueError:
                print("Please enter a positive integer for page size.")
        print(f"Using page size: {page_size}")

    # 6. Log level (optional override)
    if DEFAULT_LOG_LEVEL:
        # Already set at top
        print(f"Log level set to default: {DEFAULT_LOG_LEVEL}")
    else:
        lvl = input("Enter log level [DEBUG, INFO, WARNING, ERROR] (leave blank for INFO): ").strip().upper()
        if lvl in ("DEBUG", "INFO", "WARNING", "ERROR"):
            logger.setLevel(getattr(logging, lvl))
            print(f"Log level set to: {lvl}")
        else:
            logger.setLevel(logging.INFO)
            print("Log level set to INFO")

    # 7. CVE IDs input
    while True:
        cve_input = input("Enter CVE ID(s), separated by commas or spaces (e.g., CVE-2024-1234, CVE-2024-5678): ").strip()
        if not cve_input:
            print("Please enter at least one CVE ID.")
            continue
        cve_input_clean = cve_input.replace(",", " ")
        cve_list = [c.strip().upper() for c in cve_input_clean.split() if c.strip()]
        if not cve_list:
            print("No valid CVE IDs found. Try again.")
            continue
        invalids = [c for c in cve_list if not c.startswith("CVE-")]
        if invalids:
            print(f"Warning: these entries do not look like CVE IDs: {invalids}")
            yn = input("Proceed anyway? (y/N): ").strip().lower()
            if yn != "y":
                continue
        break
    logger.info(f"Will search for CVE(s): {cve_list}")

    # 8. Ask if QID-based lookup should be attempted first
    yn = input("Attempt QID→host search first? (y/N): ").strip().lower()
    use_qid_lookup = (yn == "y")
    if use_qid_lookup:
        logger.info("Will attempt QID-based lookup first, then fallback to direct CVE search if needed.")
    else:
        logger.info("Will perform direct CVE search only (Host List Detection API).")

    # Instantiate and run
    try:
        searcher = QualysCVESearcher(
            username=username,
            password=password,
            cert_path=cert_path,
            base_url=base_url,
            page_size=page_size
        )
        searcher.run_cve_search(cve_list, use_qid_lookup=use_qid_lookup)
    except Exception as e:
        logger.error(f"Exception during CVE search: {e}")
        sys.exit(1) 
