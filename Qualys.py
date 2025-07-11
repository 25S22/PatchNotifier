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
USERNAME        = "your_qualys_username"
PASSWORD        = "your_qualys_password"
CERT_PATH       = "/path/to/your/corporate_cert.pem"
BASE_URL        = "https://qualysapi.qg1.apps.qualys.in"
PAGE_SIZE       = 100
FILTER_OPERATOR = "CONTAINS"
LOG_LEVEL       = logging.INFO

# === LOGGER SETUP ===
logger = logging.getLogger("QualysFilteredSearch")
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("[%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(LOG_LEVEL)

class QualysSearcher:
    def __init__(self, username, password, cert_path, page_size=100):
        self.base_url    = BASE_URL.rstrip("/")
        self.session     = requests.Session()
        self.auth        = HTTPBasicAuth(username, password)
        self.cert_path   = cert_path
        self.page_size   = page_size
        self.fo_headers  = {"X-Requested-With": "Python script"}
        self.qps_headers = {
            "Content-Type": "application/xml",
            "Accept": "application/xml"
        }

    def login(self):
        url  = f"{self.base_url}/api/2.0/fo/session/"
        data = {"action": "login", "username": self.auth.username, "password": self.auth.password}
        logger.info("Logging in...")
        resp = self.session.post(url, headers=self.fo_headers, data=data, verify=self.cert_path)
        resp.raise_for_status()
        if "QualysSession" not in self.session.cookies:
            raise Exception("Login failed.")
        logger.info("Login successful.")

    def logout(self):
        url  = f"{self.base_url}/api/2.0/fo/session/"
        data = {"action": "logout"}
        try:
            self.session.post(url, headers=self.fo_headers, data=data, verify=self.cert_path)
        except Exception:
            pass
        logger.info("Logged out.")

    def build_request(self, software_name, offset):
        root    = ET.Element("ServiceRequest")
        filters = ET.SubElement(root, "filters")
        ET.SubElement(filters, "Criteria", field="installedSoftware", operator=FILTER_OPERATOR).text = software_name
        prefs   = ET.SubElement(root, "preferences")
        ET.SubElement(prefs, "startFromOffset").text = str(offset)
        ET.SubElement(prefs, "limitResults").text    = str(self.page_size)
        fields  = ET.SubElement(root, "fields")
        host    = ET.SubElement(fields, "HostAsset")
        ET.SubElement(host, "id")
        ET.SubElement(host, "dnsHostName")
        ET.SubElement(host, "netbiosName")
        swlist  = ET.SubElement(host, "HostAssetSoftwareList")
        sw      = ET.SubElement(swlist, "HostAssetSoftware")
        ET.SubElement(sw, "name")
        ET.SubElement(sw, "version")
        return ET.tostring(root, encoding="utf-8")

    def search_hosts(self, software_name):
        url     = f"{self.base_url}/qps/rest/2.0/search/am/hostasset"
        offset  = 1
        page    = 1
        results = []

        while True:
            logger.info(f"Fetching page {page}, offset {offset}...")
            body = self.build_request(software_name, offset)
            resp = self.session.post(
                url,
                headers=self.qps_headers,
                auth=self.auth,
                data=body,
                verify=self.cert_path
            )
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
            if root.findtext(".//hasMoreRecords") != "true":
                break

            offset += self.page_size
            page   += 1

        return results

    def extract_in_ranges(self, host, software_name, max_versions):
        matches = []
        host_id  = host.findtext("id", "")
        dns       = host.findtext("dnsHostName", "")
        netbios   = host.findtext("netbiosName", "")
        found     = False

        # parse and clean max_versions
        cleaned = []
        for mv in max_versions:
            try:
                cleaned.append((mv, version.parse(mv)))
            except Exception:
                logger.warning(f"Skipping invalid max_version '{mv}'")
        if not cleaned:
            return []

        # single-version logic
        if len(cleaned) == 1:
            mv_str, parsed_max = cleaned[0]
            for sw in host.findall(".//HostAssetSoftware"):
                name    = (sw.findtext("name") or "").strip()
                ver_str = (sw.findtext("version") or "").strip()
                if software_name.lower() in name.lower():
                    found = True
                    try:
                        pv = version.parse(ver_str)
                        status = "Below target" if pv < parsed_max else "Up-to-date"
                    except Exception:
                        status = "Unparsed"
                    matches.append({
                        "Host ID": host_id,
                        "DNS": dns,
                        "NetBIOS": netbios,
                        "Software": name,
                        "Version": ver_str,
                        "Status": status,
                        "Range": f"< {mv_str}"
                    })
            if not found:
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

        # multi-version logic (major.minor)
        ranges = []
        for mv_str, pv in cleaned:
            rel = getattr(pv, "release", None)
            if rel and len(rel) >= 2:
                ranges.append((rel[0], rel[1], pv, mv_str))

        if not ranges:
            return []

        for sw in host.findall(".//HostAssetSoftware"):
            name    = (sw.findtext("name") or "").strip()
            ver_str = (sw.findtext("version") or "").strip()
            if software_name.lower() in name.lower():
                found = True
                try:
                    pv  = version.parse(ver_str)
                    rel = getattr(pv, "release", None)
                except Exception:
                    continue
                if rel and len(rel) >= 2:
                    for maj, minr, pmax, mv_str in ranges:
                        if rel[0] == maj and rel[1] == minr:
                            status = "Below target" if pv <= pmax else "Up-to-date"
                            low    = f"{maj}.{minr}.0"
                            matches.append({
                                "Host ID": host_id,
                                "DNS": dns,
                                "NetBIOS": netbios,
                                "Software": name,
                                "Version": ver_str,
                                "Status": status,
                                "Range": f"{low} - {mv_str}"
                            })
                            break

        if not found:
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

    def send_email(
        self, filename, software_name, max_versions,
        cve_ids=None, cve_summaries=None,
        total=0, below=0, upto=0, notfound=0
    ):
        """
        Send email notification via Outlook draft, optionally including CVE summaries
        and summary counts.
        """
        outlook = win32.Dispatch("Outlook.Application")
        mail    = outlook.CreateItem(0)

        # Subject
        joined_max   = "/".join(max_versions)
        mail.Subject = f"[PATCH ALERT] {software_name} – Versions ≤ {joined_max}"

        # Body sections
        header = (
            f"Hello team,\n\n"
            f"Please find attached the patch status report for systems with '{software_name}' installed.\n"
            f"Target version(s): {joined_max}.\n\n"
            f"Summary:\n"
            f"  • Total Devices Evaluated: {total}\n"
            f"  • Devices Below Target Version: {below}\n"
            f"  • Devices Up-to-Date: {upto}\n"
            f"  • Software Not Found: {notfound}\n\n"
        )

        summary_section = ""
        if cve_ids and cve_summaries and len(cve_ids) == len(cve_summaries):
            summary_lines = [
                f"  • {cid}: {summ}"
                for cid, summ in zip(cve_ids, cve_summaries)
            ]
            summary_section = "CVE Details:\n" + "\n".join(summary_lines) + "\n\n"

        footer = (
            "Action Required:\n"
            "  1. Review devices marked 'Below target' in the attached report.\n"
            "  2. Plan and schedule the necessary patches.\n\n"
            "Regards,\n"
            "Patch Automation System\n"
        )

        mail.Body = header + summary_section + footer

        # Attach file
        attachment_path = os.path.abspath(filename)
        mail.Attachments.Add(attachment_path)

        # Display draft email
        mail.Display()

    def run(self, software_name, max_versions):
        self.login()
        try:
            hosts = self.search_hosts(software_name)
            logger.info(f"Found {len(hosts)} hosts.")
            all_matches = []
            for i, host in enumerate(hosts, 1):
                matches = self.extract_in_ranges(host, software_name, max_versions)
                all_matches.extend(matches or [])
                if i % 100 == 0:
                    logger.info(f"Processed {i}/{len(hosts)} hosts")

            filename = f"{software_name.replace(' ', '_')}_versions_{'_'.join(max_versions)}.xlsx"
            if not all_matches:
                logger.info("No matching records found.")
                # create empty DataFrame & save
                df = pd.DataFrame(columns=[
                    "Host ID", "DNS", "NetBIOS",
                    "Software", "Version", "Status", "Range"
                ])
                df.to_excel(filename, index=False)
                logger.info(f"Saved empty Excel: {filename}")
                # send email with zero counts
                self.send_email(filename, software_name, max_versions)
                return

            df = pd.DataFrame(all_matches)
            cat = pd.CategoricalDtype(
                categories=["Below target", "Up-to-date", "Not Found"],
                ordered=True
            )
            df["Status"] = df["Status"].astype(cat)
            df = df.sort_values(["Status", "Host ID"])
            df.to_excel(filename, index=False)
            logger.info(f"Saved Excel: {filename}")

            # compute summary counts
            counts = df["Status"].value_counts().to_dict()
            total   = len(df)
            below   = counts.get("Below target", 0)
            upto    = counts.get("Up-to-date",    0)
            notfound= counts.get("Not Found",     0)

            # send email with stats
            self.send_email(
                filename, software_name, max_versions,
                cve_ids=None, cve_summaries=None,
                total=total, below=below,
                upto=upto, notfound=notfound
            )
        finally:
            self.logout()

def main():
    software      = input("Enter software name: ").strip()
    max_ver_input = input("Enter version(s) separated by '/': ").strip()
    if not software or not max_ver_input:
        print("Missing inputs.")
        sys.exit(1)
    max_versions = [v.strip() for v in max_ver_input.split("/") if v.strip()]
    qs = QualysSearcher(USERNAME, PASSWORD, CERT_PATH, page_size=PAGE_SIZE)
    qs.run(software, max_versions)

if __name__ == "__main__":
    main()
