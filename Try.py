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
        max_versions: list of strings like ["8.0.10", "9.0.12", ...] or a single-element list ["11.0.7"].

        Behavior:
        - If only one version in max_versions:
            * parsed_max = version.parse(max_versions[0]).
            * For every installed software entry whose name matches (we use substring match: software_name.lower() in name.lower()):
                - parsed_ver = version.parse(ver_str). If parsed_ver < parsed_max => "Below target", else => "Up-to-date".
            * If no matching software entries at all on this host => one row with Status "Not Found".
        - If multiple versions in max_versions:
            * Pre-parse each into (major, minor, parsed_lower, parsed_max).
              parsed_lower = version.parse(f"{major}.{minor}.0") – grouping by first two segments.
            * For each installed software entry matching name:
                - parsed_ver = version.parse(ver_str).
                - Check if parsed_ver.release has same major/minor as any range:
                    - If so, compare parsed_ver <= parsed_max? "Below target" : "Up-to-date".
                    - Skip versions whose major.minor are not in any specified range.
            * If no matching software entries at all => one row with Status "Not Found".
        """
        matches = []
        host_id = host.findtext("id", "")
        dns = host.findtext("dnsHostName", "")
        netbios = host.findtext("netbiosName", "")
        found_software = False

        # Validate and parse max_versions
        cleaned = []
        for mv in max_versions:
            mv = mv.strip()
            if not mv:
                continue
            try:
                parsed = version.parse(mv)
                cleaned.append((mv, parsed))
            except Exception:
                logger.warning(f"Skipping invalid max_version '{mv}'")
        if not cleaned:
            # No valid versions: we skip all comparisons, return empty so host is effectively ignored.
            return []

        # Single-version logic
        if len(cleaned) == 1:
            mv_str, parsed_max = cleaned[0]
            # For substring matching in software name:
            for sw in host.findall(".//HostAssetSoftware"):
                name = (sw.findtext("name") or "").strip()
                ver_str = (sw.findtext("version") or "").strip()
                if software_name.lower() in name.lower():
                    found_software = True
                    try:
                        parsed_ver = version.parse(ver_str)
                    except Exception:
                        logger.warning(f"Invalid version format: '{ver_str}' on host {host_id}")
                        # Record as unparsed?
                        matches.append({
                            "Host ID": host_id,
                            "DNS": dns,
                            "NetBIOS": netbios,
                            "Software": name,
                            "Version": ver_str,
                            "Status": "Unparsed",
                            "Range": f"< {mv_str}"
                        })
                        continue

                    # Compare across entire version:
                    if parsed_ver < parsed_max:
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
                        "Range": f"< {mv_str}"
                    })
            if not found_software:
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

        # Multiple-version (range) logic
        # Pre-parse into (major, minor, parsed_lower, parsed_max) for grouping by major.minor
        ranges = []
        for mv_str, parsed in cleaned:
            rel = getattr(parsed, "release", None)
            if rel and len(rel) >= 2:
                major, minor = rel[0], rel[1]
            elif rel and len(rel) == 1:
                major, minor = rel[0], 0
            else:
                # Cannot determine major/minor => skip
                logger.warning(f"Cannot extract major/minor from '{mv_str}', skipping range logic for it.")
                continue
            lower_str = f"{major}.{minor}.0"
            try:
                parsed_lower = version.parse(lower_str)
            except Exception:
                parsed_lower = None
            ranges.append((major, minor, parsed_lower, parsed, mv_str))

        if not ranges:
            # No usable ranges parsed; treat as no filtering
            return []

        for sw in host.findall(".//HostAssetSoftware"):
            name = (sw.findtext("name") or "").strip()
            ver_str = (sw.findtext("version") or "").strip()
            if software_name.lower() in name.lower():
                found_software = True
                try:
                    parsed_ver = version.parse(ver_str)
                except Exception:
                    logger.warning(f"Invalid version format: '{ver_str}' on host {host_id}")
                    # Optionally record unparsed
                    continue

                # Find matching range by major.minor
                matched = False
                rv = getattr(parsed_ver, "release", None)
                if rv and len(rv) >= 2:
                    for major, minor, parsed_lower, parsed_max, mv_str in ranges:
                        if rv[0] == major and rv[1] == minor:
                            matched = True
                            if parsed_ver <= parsed_max:
                                status = "Below target"
                            else:
                                status = "Up-to-date"
                            # Range description: e.g. "8.0.0 - 8.0.10"
                            low_descr = f"{major}.{minor}.0"
                            matches.append({
                                "Host ID": host_id,
                                "DNS": dns,
                                "NetBIOS": netbios,
                                "Software": name,
                                "Version": ver_str,
                                "Status": status,
                                "Range": f"{low_descr} - {mv_str}"
                            })
                            break
                # If version's major.minor not in any specified ranges => skip
                if not matched:
                    pass

        if not found_software:
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
        mail.Subject = f"[PATCH ALERT] Devices with {software_name} (max: {joined_max})"
        mail.Body = f"""
Hello,

Please find attached the list of devices where '{software_name}' is installed, evaluated against specified version(s) '{joined_max}', indicating below-target or up-to-date statuses.

Take appropriate patching action.

Regards,
Patch Automation System
        """.strip()
        mail.Attachments.Add(os.path.abspath(filename))
        mail.Display()  # Opens the draft

    def run(self, software_name, max_versions):
        """
        software_name: str
        max_versions: list of strings, e.g. ["11.0.7"] or ["8.0.10","9.0.12","10.1.2"]
        """
        self.login()
        try:
            hosts = self.search_hosts(software_name)
            logger.info(f"Found {len(hosts)} hosts.")
            all_matches = []
            for i, host in enumerate(hosts, 1):
                matches = self.extract_in_ranges(host, software_name, max_versions)
                if matches:
                    all_matches.extend(matches)
                if i % 100 == 0:
                    logger.info(f"Processed {i}/{len(hosts)} hosts")

            if not all_matches:
                logger.info("No matching records found for the specified version(s).")
                df_empty = pd.DataFrame(columns=["Host ID", "DNS", "NetBIOS", "Software", "Version", "Status", "Range"])
                filename = f"{software_name.replace(' ', '_')}_versions_{'_'.join(max_versions)}.xlsx"
                df_empty.to_excel(filename, index=False)
                logger.info(f"Saved empty Excel: {filename}")
                # Optionally send email for empty
                self.send_email(filename, software_name, max_versions)
                return

            df = pd.DataFrame(all_matches)
            # Sort so that "Below target" come first, then "Up-to-date", then "Not Found" if present.
            cat_type = pd.CategoricalDtype(categories=["Below target", "Up-to-date", "Not Found"], ordered=True)
            if "Status" in df.columns:
                df["Status"] = df["Status"].astype(cat_type)
                df = df.sort_values(by=["Status", "Host ID"])

            filename = f"{software_name.replace(' ', '_')}_versions_{'_'.join(max_versions)}.xlsx"
            df.to_excel(filename, index=False)
            logger.info(f"Saved Excel: {filename}")
            self.send_email(filename, software_name, max_versions)
        finally:
            self.logout()


def main():
    software = input("Enter software name (case-insensitive substring match): ").strip()
    max_ver_input = input("Enter version(s) separated by '/': ").strip()
    if not software or not max_ver_input:
        print("Missing software/version input.")
        sys.exit(1)

    max_versions = [v.strip() for v in max_ver_input.split("/") if v.strip()]
    if not max_versions:
        print("No valid versions parsed.")
        sys.exit(1)

    # Optional: validate parseable, but extract_in_ranges also checks
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
