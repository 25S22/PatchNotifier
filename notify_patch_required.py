import datetime
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
RATE_LIMIT_DELAY = 6  # seconds between app scans

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

    for i, app in enumerate(applications, 1):
        product = app.get("product")
        if not product:
            continue
        logger.info("[%d/%d] Scanning CVEs for %s", i, len(applications), product)

        # Fetch & club CVEs
        matched, clubbed = fetch_recent_cves(product, days_back=days_back)
        combined = matched + clubbed
        logger.info("  Found %d CVEs for %s", len(combined), product)

        # Save audit log
        ensure_audit_folder_exists()
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', product.lower())
        log_path = os.path.join(AUDIT_LOG_FOLDER, f"{sanitized}_cve_{ts}.json")
        save_audit_log(combined, custom_path=log_path)

        # Prepare lists
        cve_ids       = [e['cve_id']  for e in combined]
        cve_summaries = [e['summary'] for e in combined]
        versions      = list({e['version'] for e in combined if e['version'] and e['version'] != 'Unknown'})

        # Run Qualys search
        if versions:
            logger.info("  Running Qualys for versions: %s", versions)
            try:
                qs.run(product, versions)
            except Exception as e:
                logger.error("  Qualys run error for %s %s: %s", product, versions, e)
        else:
            logger.info("  Skipping Qualys for %s: No valid versions", product)

        # Collect & email (with summaries)
        try:
            filename, vuln_count, det_count = qs.collect_results()
            qs.send_email(
                filename=filename,
                software_name=product,
                max_versions=versions,
                cve_ids=cve_ids,
                cve_summaries=cve_summaries
            )
        except AttributeError:
            logger.warning("QualysSearcher.collect_results/send_email signature may need updating.")

        if i < len(applications):
            logger.info("Sleeping %ds to respect rate limits...", RATE_LIMIT_DELAY)
            time.sleep(RATE_LIMIT_DELAY)

    logger.info("Integration complete.")

if __name__ == "__main__":
    integrate_cve_to_qualys()
