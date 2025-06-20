import datetime
import re
import os
import time
import logging
import sys

from cve import fetch_recent_cves, ensure_audit_folder_exists, load_applications, save_audit_log
from qualys import QualysSearcher, USERNAME as QUALYS_USERNAME, PASSWORD as QUALYS_PASSWORD, CERT_PATH as QUALYS_CERT_PATH

# === CONFIGURATION ===
# Optionally override number of days back via CLI arg
DAYS_BACK = int(sys.argv[1]) if len(sys.argv) > 1 else 7
# Override Qualys page size (e.g., 1000)
QUALYS_PAGE_SIZE = 1000  

# === LOGGER SETUP ===
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger()


def integrate_cve_to_qualys(days_back: int = DAYS_BACK):
    """
    Runs the CVE scanner, logs results, then for each CVE entry with a known version,
    invokes QualysSearcher to generate the version report and dispatch the email.
    Fixes paging size and suppresses duplicate logging.
    """
    logger.info("Starting integrated CVE→Qualys workflow (last %d days)...", days_back)

    # Load monitored applications
    applications = load_applications()

    # Instantiate QualysSearcher with desired page size
    qs = QualysSearcher(
        username=QUALYS_USERNAME,
        password=QUALYS_PASSWORD,
        cert_path=QUALYS_CERT_PATH,
        page_size=QUALYS_PAGE_SIZE
    )

    # Suppress duplicate QualysFilteredSearch logs
    qualys_logger = logging.getLogger("QualysFilteredSearch")
    qualys_logger.propagate = False

    for app in applications:
        product = app.get("product")
        if not product:
            continue
        logger.info("Scanning CVEs for %s", product)

        # Fetch CVE entries
        matched, single = fetch_recent_cves(product, days_back=days_back)
        combined = matched + single
        logger.info("Found %d CVEs for %s", len(combined), product)

        # Save per-app audit log
        ensure_audit_folder_exists()
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', product.lower())
        log_path = os.path.join("./audit_logs", f"{sanitized}_cve_{ts}.json")
        save_audit_log(combined, custom_path=log_path)

        # Feed each CVE's version into Qualys
        for entry in combined:
            version_str = entry.get("version", "Unknown")
            if version_str and version_str != "Unknown":
                versions = version_str.split("/")
                logger.info("Running Qualys for %s versions %s", product, versions)
                try:
                    qs.run(product, versions)
                except Exception as e:
                    logger.error("Qualys run error for %s %s: %s", product, versions, e)
            else:
                logger.info("Skipping Qualys for %s: Unknown version", product)

        # Throttle between products
        time.sleep(5)

    logger.info("Integration complete.")


if __name__ == "__main__":
    integrate_cve_to_qualys()
