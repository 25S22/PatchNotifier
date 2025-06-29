import datetime
import re
import os
import time
import logging
import sys

from cve import (
    fetch_recent_cves,
    ensure_audit_folder_exists,
    load_applications,
    save_audit_log
)
from qualys import QualysSearcher, USERNAME as QUALYS_USERNAME, PASSWORD as QUALYS_PASSWORD, CERT_PATH as QUALYS_CERT_PATH

# === CONFIGURATION ===
DAYS_BACK         = int(sys.argv[1]) if len(sys.argv) > 1 else 7
QUALYS_PAGE_SIZE  = 1000
RATE_LIMIT_DELAY  = 6      # seconds between app scans
AUDIT_LOG_FOLDER  = "audit_logs"   # ← NEW

# === LOGGER SETUP ===
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("integrate")  # root for this script
# Prevent double‐logging from the QualysSearcher logger:
q_logger = logging.getLogger("QualysFilteredSearch")
q_logger.propagate = False        # ← CHANGED
q_logger.setLevel(logging.WARNING)

def integrate_cve_to_qualys(days_back: int = DAYS_BACK):
    logger.info("Starting integrated CVE→Qualys workflow (last %d days)...", days_back)

    ensure_audit_folder_exists(AUDIT_LOG_FOLDER)   # ← ensure folder is created once
    applications = load_applications()

    # instantiate once
    qs = QualysSearcher(
        username=QUALYS_USERNAME,
        password=QUALYS_PASSWORD,
        cert_path=QUALYS_CERT_PATH,
        page_size=QUALYS_PAGE_SIZE
    )

    for idx, app in enumerate(applications, start=1):
        product = app.get("product")
        if not product:
            continue

        logger.info("[%d/%d] Processing %s", idx, len(applications), product)

        # 1) fetch CVEs
        matched, clubbed = fetch_recent_cves(product, days_back=days_back)
        combined = matched + clubbed
        logger.info("  Found %d CVEs for %s", len(combined), product)

        # 2) write audit log
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", product.lower())
        log_path = os.path.join(AUDIT_LOG_FOLDER, f"{safe_name}_cve_{ts}.json")
        save_audit_log(combined, custom_path=log_path)
        logger.info("  Audit log saved → %s", log_path)

        # 3) prepare version list and CVE fields
        cve_ids       = [c["cve_id"]  for c in combined]
        cve_summaries = [c["summary"] for c in combined]
        versions      = sorted({c["version"] for c in combined if c.get("version") and c["version"] != "Unknown"})

        if not versions:
            logger.info("  No valid versions for %s; skipping Qualys.", product)
        else:
            logger.info("  Running Qualys search for versions: %s", versions)

            # ← RUN but *do not* let run() send its own email:
            qs.run(product, versions, send_email=False)  

            # ← collect the filename and status counts out of the QS instance:
            filename, counts = qs.collect_results()  
            total   = counts.get("total",    0)
            below   = counts.get("below",    0)
            upto    = counts.get("upto",     0)
            notfound= counts.get("notfound", 0)

            # 4) now send one consolidated email, with CVE details and counts:
            qs.send_email(
                filename=filename,
                software_name=product,
                max_versions=versions,
                cve_ids=cve_ids,
                cve_summaries=cve_summaries,
                total=total,
                below=below,
                upto=upto,
                notfound=notfound
            )

        # rate‐limit between applications
        if idx < len(applications):
            logger.info("Sleeping %d seconds to respect rate limits...", RATE_LIMIT_DELAY)
            time.sleep(RATE_LIMIT_DELAY)

    logger.info("Integration complete.")

if __name__ == "__main__":
    integrate_cve_to_qualys()
