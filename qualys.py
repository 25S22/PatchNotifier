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

def get_host_details(session, host_id, software_name):
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

    found = False
    for sw in host.findall(".//HostAssetSoftware"):
        name = sw.findtext("name", "").strip()
        version = sw.findtext("version", "UNKNOWN").strip()

        if name.lower() == software_name.lower():
            try:
                if version != "UNKNOWN" and parse_version(version) < parse_version(MIN_VERSION):
                    return {
                        "id": host_id,
                        "dns": dns,
                        "netbios": netbios,
                        "version": version
                    }
                else:
                    return None
            except Exception:
                # Fallback: can't parse version
                return None
    return None

def main():
    print("=== Qualys Asset Software Version Filter ===")
    username = input("Qualys Username: ")
    password = getpass.getpass("Password (input hidden): ")
    software_name = input("Software to search: ").strip()

    session = requests.Session()
    try:
        login(session, username, password)
        host_ids = search_host_assets(session, software_name)

        filtered_hosts = []
        for i, hid in enumerate(host_ids, 1):
            try:
                result = get_host_details(session, hid, software_name)
                if result:
                    filtered_hosts.append(result)
                    print(f"[{i}/{len(host_ids)}] ✓ {result['dns']} | v{result['version']}")
                else:
                    print(f"[{i}/{len(host_ids)}] ✗ Version >= {MIN_VERSION} or not found")
            except Exception as e:
                print(f"[{i}/{len(host_ids)}] ⚠️ Error for Host ID {hid}: {e}")

        out_file = f"filtered_{software_name.replace(' ', '_')}_under_{MIN_VERSION}.csv"
        with open(out_file, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["id", "dns", "netbios", "version"])
            writer.writeheader()
            writer.writerows(filtered_hosts)

        print(f"[✓] Results written to: {out_file}")

    finally:
        logout(session)

if __name__ == "__main__":
    main()
