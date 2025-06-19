import requests
import xml.etree.ElementTree as ET
import getpass
import csv
from packaging.version import parse as parse_version

BASE_URL = "https://qualysapi.qg1.apps.qualys.com"
PAGE_SIZE = 100
MIN_VERSION = "115.0.0"

def login(session, username, password):
    url = f"{BASE_URL}/api/2.0/fo/session/"
    data = {"action": "login", "username": username, "password": password}
    headers = {"X-Requested-With": "PythonScript"}
    r = session.post(url, data=data, headers=headers)
    if "QualysSession" not in session.cookies:
        raise Exception("❌ Login failed. Check credentials.")
    print("[✓] Logged in successfully.")

def logout(session):
    url = f"{BASE_URL}/api/2.0/fo/session/"
    session.post(url, data={"action": "logout"}, headers={"X-Requested-With": "PythonScript"})
    print("[✓] Logged out.")

def search_host_assets(session, software_name):
    all_ids = []
    last_record_id = None
    print(f"[*] Searching for hosts with software: {software_name}...")

    while True:
        body = ET.Element("ServiceRequest")
        filters = ET.SubElement(body, "filters")
        criteria = ET.SubElement(filters, "Criteria", field="installedSoftware", operator="EQUALS")
        criteria.text = software_name

        prefs = ET.SubElement(body, "preferences")
        ET.SubElement(prefs, "pageSize").text = str(PAGE_SIZE)
        if last_record_id:
            ET.SubElement(prefs, "lastRecordId").text = last_record_id

        xml_data = ET.tostring(body, encoding="utf-8")
        headers = {
            "X-Requested-With": "PythonScript",
            "Content-Type": "application/xml",
            "Accept": "application/xml"
        }

        url = f"{BASE_URL}/qps/rest/2.0/search/am/hostasset"
        r = session.post(url, data=xml_data, headers=headers)
        r.raise_for_status()

        root = ET.fromstring(r.content)
        ids = [e.text for e in root.findall(".//HostAsset/id")]

        if not ids:
            print("[✗] No HostAssets found in current page.")
            break

        all_ids.extend(ids)
        print(f"[→] Retrieved {len(ids)} IDs. Total so far: {len(all_ids)}")

        has_more = root.findtext('.//hasMoreRecords') == "true"
        if has_more:
            last_record_id = ids[-1]
        else:
            break

    print(f"[✓] Total HostAsset IDs collected: {len(all_ids)}")
    return all_ids

def is_version_below_target(version, min_version):
    """
    Check if version is below target version(s).
    Supports both single version and range format with '/' separator.
    """
    if "/" in min_version:
        # Handle multiple version ranges (e.g., "2.1/3.4")
        version_targets = min_version.split("/")
        try:
            parsed_version = parse_version(version)
            for target in version_targets:
                target = target.strip()
                if parsed_version < parse_version(target):
                    return True
            return False
        except Exception:
            return False
    else:
        # Single version comparison
        try:
            return parse_version(version) < parse_version(min_version)
        except Exception:
            return False

def get_host_details(session, host_id, software_name, min_version):
    url = f"{BASE_URL}/qps/rest/2.0/get/am/hostasset/{host_id}"
    headers = {
        "X-Requested-With": "PythonScript",
        "Content-Type": "application/xml",
        "Accept": "application/xml"
    }

    req_xml = ET.Element("ServiceRequest")
    ET.SubElement(req_xml, "id").text = host_id
    r = session.post(url, data=ET.tostring(req_xml), headers=headers)
    r.raise_for_status()

    root = ET.fromstring(r.content)
    host = root.find(".//HostAsset")
    if host is None:
        return None

    dns = host.findtext("dnsHostName", default="N/A")
    netbios = host.findtext("netbiosName", default="N/A")

    for sw in host.findall(".//HostAssetSoftware"):
        name = sw.findtext("name", "").strip()
        version = sw.findtext("version", "UNKNOWN").strip()

        if name.lower() == software_name.lower():
            if version != "UNKNOWN" and is_version_below_target(version, min_version):
                return {
                    "id": host_id,
                    "dns": dns,
                    "netbios": netbios,
                    "version": version,
                    "software_name": name,
                    "status": "Below Target Version"
                }
            else:
                return {
                    "id": host_id,
                    "dns": dns,
                    "netbios": netbios,
                    "version": version,
                    "software_name": name,
                    "status": "Above/Equal Target Version" if version != "UNKNOWN" else "Version Unknown"
                }
    return None

def main():
    print("=== Qualys Asset Software Version Filter ===")
    username = input("Qualys Username: ")
    password = getpass.getpass("Password (input hidden): ")
    software_name = input("Software to search: ").strip()
    
    # Allow user to specify custom version or use default
    custom_version = input(f"Target version (default: {MIN_VERSION}, supports ranges like '2.1/3.4'): ").strip()
    target_version = custom_version if custom_version else MIN_VERSION

    session = requests.Session()
    try:
        login(session, username, password)
        host_ids = search_host_assets(session, software_name)

        if not host_ids:
            print("[!] No hosts found with the specified software.")
            # Still create empty CSV file for tracking
            out_file = f"filtered_{software_name.replace(' ', '_')}_under_{target_version.replace('/', '_')}.csv"
            with open(out_file, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["id", "dns", "netbios", "version", "software_name", "status"])
                writer.writeheader()
            print(f"[✓] Empty results file created: {out_file}")
            return

        all_hosts = []
        filtered_hosts = []
        
        for i, hid in enumerate(host_ids, 1):
            try:
                result = get_host_details(session, hid, software_name, target_version)
                if result:
                    all_hosts.append(result)
                    if result["status"] == "Below Target Version":
                        filtered_hosts.append(result)
                        print(f"[{i}/{len(host_ids)}] ✓ {result['dns']} | v{result['version']} (BELOW TARGET)")
                    else:
                        print(f"[{i}/{len(host_ids)}] ✗ {result['dns']} | v{result['version']} ({result['status']})")
                else:
                    print(f"[{i}/{len(host_ids)}] ⚠️ Software not found on host")
            except Exception as e:
                print(f"[{i}/{len(host_ids)}] ⚠️ Error for Host ID {hid}: {e}")

        # Always create CSV file - include all hosts found with the software
        out_file = f"filtered_{software_name.replace(' ', '_')}_under_{target_version.replace('/', '_')}.csv"
        
        # If we have any hosts with the software, write them all to CSV
        hosts_to_write = all_hosts if all_hosts else []
        
        with open(out_file, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["id", "dns", "netbios", "version", "software_name", "status"])
            writer.writeheader()
            writer.writerows(hosts_to_write)

        print(f"\n[✓] Results Summary:")
        print(f"    Total hosts with {software_name}: {len(all_hosts)}")
        print(f"    Hosts below target version ({target_version}): {len(filtered_hosts)}")
        print(f"    Results written to: {out_file}")
        
        if "/" in target_version:
            print(f"    Note: Using range-based filtering - versions below ANY of: {target_version.replace('/', ' OR ')}")

    finally:
        logout(session)

if __name__ == "__main__":
    main()
