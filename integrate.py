# integration.py

import json
import datetime
import requests
import re
import os
import time
import logging
import sys

from cve import fetch_recent_cves, ensure_audit_folder_exists, load_applications, save_audit_log
from qualys import QualysSearcher, USERNAME as QUALYS_USERNAME, PASSWORD as QUALYS_PASSWORD, CERT_PATH as QUALYS_CERT_PATH

# === CONFIGURATION ===
DAYS_BACK = int(sys.argv[1]) if len(sys.argv) > 1 else 7
QUALYS_PAGE_SIZE = 1000  

# === LOGGER SETUP ===
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger()

def integrate_cve_to_qualys(days_back: int = DAYS_BACK):
    logger.info("Starting integrated CVE→Qualys workflow (last %d days)...", days_back)
    applications = load_applications()

    qs = QualysSearcher(
        username=QUALYS_USERNAME,
        password=QUALYS_PASSWORD,
        cert_path=QUALYS_CERT_PATH,
        page_size=QUALYS_PAGE_SIZE
    )
    # Silence QualysFilteredSearch noise
    logging.getLogger("QualysFilteredSearch").propagate = False

    for app in applications:
        product = app.get("product")
        if not product:
            continue
        logger.info("Scanning CVEs for %s", product)

        matched, single = fetch_recent_cves(product, days_back=days_back)
        combined = matched + single
        logger.info("Found %d CVEs for %s", len(combined), product)

        # write per-app log
        ensure_audit_folder_exists()
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', product.lower())
        log_path = os.path.join("./audit_logs", f"{sanitized}_cve_{ts}.json")
        save_audit_log(combined, custom_path=log_path)

        # Prepare lists for Qualys + Email
        cve_ids       = [e["cve_id"]   for e in combined]
        cve_versions  = [e["version"]  for e in combined]
        cve_summaries = [e["summary"]  for e in combined]

        # Run Qualys for each version group
        for version_str in set(cve_versions):
            if version_str and version_str != "Unknown":
                versions = version_str.split("/")
                logger.info("Running Qualys for %s versions %s", product, versions)
                try:
                    qs.run(product, versions)
                except Exception as e:
                    logger.error("Qualys run error for %s %s: %s", product, versions, e)
            else:
                logger.info("Skipping Qualys for %s: Unknown version", product)

        # Once Qualys reports are generated, dispatch email including summaries:
        # Assume QualysSearcher.collect_results() returns (filename, vuln_count, detection_count)
        try:
            filename, vuln_count, det_count = qs.collect_results()
            qs.send_email(
                filename,
                cve_ids,
                cve_summaries,
                vulnerable_count=vuln_count,
                total_detections=det_count
            )
        except AttributeError:
            logger.warning("QualysSearcher has no collect_results/send_email method signature updated.")

        time.sleep(5)

    logger.info("Integration complete.")

if __name__ == "__main__":
    integrate_cve_to_qualys()
