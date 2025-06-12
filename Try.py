import requests
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
import pandas as pd
from packaging import version
import logging
import sys
import os
import win32com.client as win32

# === CONFIGURATION ===
USERNAME = "your_qualys_username"
PASSWORD = "your_qualys_password"
CERT_PATH = "/path/to/your/corporate_cert.pem"
BASE_URL = "https://qualysapi.qg1.apps.qualys.in"
PAGE_SIZE = 100
FILTER_OPERATOR = "CONTAINS"
LOG_LEVEL = logging.INFO

# === LOGGER SETUP ===
logger = logging.getLogger("QualysFilteredSearch")
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("[%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(LOG_LEVEL)

class QualysSearcher:
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
        url = f"{self.base_url}/api/2.0/fo/session/"
        data = {"action": "logout"}
        try:
            self.session.post(url, headers=self.fo_headers, data=data, verify=self.cert_path)
        except Exception:
            pass
        logger.info("Logged out.")

    def build_request(self, software_name, offset):
        root = ET.Element("ServiceRequest")
        filters = ET.SubElement(root, "filters")
        ET.SubElement(filters, "Criteria", field="installedSoftware", operator=FILTER_OPERATOR).text = software_name
        prefs = ET.SubElement(root, "preferences")
        ET.SubElement(prefs, "startFromOffset").text = str(offset)
        ET.SubElement(prefs, "limitResults").text = str(self.page_size)
        fields = ET.SubElement(root, "fields")
        host = ET.SubElement(fields, "HostAsset")
        ET.SubElement(host, "id")
        ET.SubElement(host, "dnsHostName")
        ET.SubElement(host, "netbiosName")
        swlist = ET.SubElement(host, "HostAssetSoftwareList")
        sw = ET.SubElement(swlist, "HostAssetSoftware")
        ET.SubElement(sw, "name")
        ET.SubElement(sw, "version")
        return ET.tostring(root, encoding="utf-8")

    def search_hosts(self, software_name):
        url = f"{self.base_url}/qps/rest/2.0/search/am/hostasset"
        offset, page = 1, 1
        results = []

        while True:
            logger.info(f"Fetching page {page}, offset {offset}...")
            body = self.build_request(software_name, offset)
            resp = self.session.post(url, headers=self.qps_headers, auth=self.auth, data=body, verify=self.cert_path)
            if resp.status_code == 403:
                raise Exception("Forbidden. Check access/credentials.")
            resp.raise_for_status()

            try:
                root = ET.fromstring(resp.content)
            except ET.ParseError:
                raise Exception("Malformed XML response.")

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

    def extract_in_ranges(self, host, software_name, max_versions):
        """
        For a given host (Element), look for installed software entries matching software_name.
        max_versions: list of strings like ["8.0.10", "9.0.12", ...].
        For each found software version:
         - If major/minor matches a max_version entry:
            - lower bound = X.Y.0
            - if ver <= max_version: status "Below target"
            - else (ver > max_version): status "Up-to-date"
         - If no max_version's major/minor matches this version: skip (do not include in output for that host software instance)
        If software_name not found on host at all: return a single entry with Status "Not Found"
        """
        matches = []
        host_id = host.findtext("id", "")
        dns = host.findtext("dnsHostName", "")
        netbios = host.findtext("netbiosName", "")
        found_software = False

        # Pre-parse max_versions into tuples: (major:int, minor:int, parsed_max_version:Version)
        ranges = []
        for max_v in max_versions:
            try:
                parsed = version.parse(max_v)
                # Extract major, minor from parsed.release
                rel = parsed.release
                if len(rel) >= 2:
                    major, minor = rel[0], rel[1]
                elif len(rel) == 1:
                    major, minor = rel[0], 0
                else:
                    # fallback
                    continue
                lower_str = f"{major}.{minor}.0"
                parsed_lower = version.parse(lower_str)
                ranges.append((major, minor, parsed_lower, parsed))
            except Exception:
                logger.warning(f"Skipping invalid max_version '{max_v}'")
                continue

        # If no valid ranges parsed, we treat as no filtering: nothing will be included.
        for sw in host.findall(".//HostAssetSoftware"):
            name = (sw.findtext("name") or "").strip()
            ver_str = (sw.findtext("version") or "").strip()
            if software_name.lower() in name.lower():
                found_software = True
                try:
                    parsed_ver = version.parse(ver_str)
                except Exception:
                    logger.warning(f"Invalid version format: '{ver_str}' on host {host_id}")
                    continue

                # Determine if parsed_ver matches any of the ranges by major/minor
                matched_range = False
                for major, minor, parsed_lower, parsed_max in ranges:
                    # only consider if same major.minor
                    rv = parsed_ver.release
                    if len(rv) >= 2 and rv[0] == major and rv[1] == minor:
                        matched_range = True
                        if parsed_ver <= parsed_max:
                            status = "Below target"
                        else:
                            status = "Up-to-date"
                        matches.append({
                            "Host ID": host_id,
                            "DNS": dns,
                            "NetBIOS": netbios,
                            "Software": name,
                            "Version": ver_str,
                            "Status": status,
                            "Range": f"{major}.{minor}.0 - {parsed_max}"
                        })
                        break

                # If version exists but its major.minor not in any specified ranges, skip including it.
                # (Alternatively, you could record "Out of specified ranges" if desired.)
                if not matched_range:
                    # skip this version instance
                    pass

        if not found_software:
            # if you want to include hosts without the software, uncomment below:
            matches.append({
                "Host ID": host_id,
                "DNS": dns,
                "NetBIOS": netbios,
                "Software": software_name,
                "Version": "",
                "Status": "Not Found",
                "Range": ""
            })

        return matches

    def send_email(self, filename, software_name, max_versions):
        outlook = win32.Dispatch("Outlook.Application")
        mail = outlook.CreateItem(0)
        joined_max = "/".join(max_versions)
        mail.Subject = f"[PATCH ALERT] Devices with {software_name} in ranges {joined_max}"
        mail.Body = f"""
Hello,

Please find attached the list of devices where '{software_name}' is installed with versions in or above the specified ranges '{joined_max}', indicating below-target or up-to-date statuses.

Take appropriate patching action.

Regards,
Patch Automation System
        """.strip()
        mail.Attachments.Add(os.path.abspath(filename))
        mail.Display()  # Opens the draft

    def run(self, software_name, max_versions):
        """
        software_name: str
        max_versions: list of strings, e.g. ["8.0.10", "9.0.12", "10.1.2"]
        """
        # Login
        self.login()
        try:
            hosts = self.search_hosts(software_name)
            logger.info(f"Found {len(hosts)} hosts.")
            all_matches = []
            for i, host in enumerate(hosts, 1):
                matches = self.extract_in_ranges(host, software_name, max_versions)
                # Only add if matches non-empty
                if matches:
                    all_matches.extend(matches)
                if i % 100 == 0:
                    logger.info(f"Processed {i}/{len(hosts)} hosts")

            if not all_matches:
                logger.info("No matching records found for the specified ranges.")
                # Still create an empty file to show structure
                df_empty = pd.DataFrame(columns=["Host ID", "DNS", "NetBIOS", "Software", "Version", "Status", "Range"])
                filename = f"{software_name.replace(' ', '_')}_ranges_{'_'.join(max_versions)}.xlsx"
                df_empty.to_excel(filename, index=False)
                logger.info(f"Saved empty Excel: {filename}")
                # Optionally send an email even if empty
                self.send_email(filename, software_name, max_versions)
                return

            df = pd.DataFrame(all_matches)
            # Sort so that "Below target" come first, then "Up-to-date", then "Not Found" if present.
            # Define categorical ordering
            cat_type = pd.CategoricalDtype(categories=["Below target", "Up-to-date", "Not Found"], ordered=True)
            if "Status" in df.columns:
                df["Status"] = df["Status"].astype(cat_type)
                df = df.sort_values(by=["Status", "Host ID"])  # secondary sort by Host ID, if desired

            # Save to Excel
            filename = f"{software_name.replace(' ', '_')}_ranges_{'_'.join(max_versions)}.xlsx"
            df.to_excel(filename, index=False)
            logger.info(f"Saved Excel: {filename}")
            # Send email with attachment
            self.send_email(filename, software_name, max_versions)
        finally:
            self.logout()


def main():
    software = input("Enter software name (case-insensitive exact match): ").strip()
    max_ver_input = input("Enter max allowed versions separated by '/': ").strip()
    if not software or not max_ver_input:
        print("Missing software/version input.")
        sys.exit(1)

    # Split and strip; e.g. "8.0.10/9.0.12/10.1.2"
    max_versions = [v.strip() for v in max_ver_input.split("/") if v.strip()]
    if not max_versions:
        print("No valid versions parsed.")
        sys.exit(1)

    # Optional: Validate each version string can be parsed
    valid_versions = []
    for v in max_versions:
        try:
            _ = version.parse(v)
            valid_versions.append(v)
        except Exception:
            print(f"Warning: '{v}' is not a valid version string and will be skipped.")
    if not valid_versions:
        print("No valid version strings provided.")
        sys.exit(1)

    qs = QualysSearcher(USERNAME, PASSWORD, CERT_PATH, page_size=PAGE_SIZE)
    qs.run(software, valid_versions)


if __name__ == "__main__":
    main()
