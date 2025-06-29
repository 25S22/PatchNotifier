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
RATE_LIMIT_DELAY  = 6
AUDIT_LOG_FOLDER  = "audit_logs"
OUTPUT_FOLDER     = "results"

# === LOGGER SETUP ===
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("integrate")
q_logger = logging.getLogger("QualysFilteredSearch")
q_logger.propagate = False
q_logger.setLevel(logging.WARNING)

def sanitize_filename(s: str) -> str:
    return re.sub(r"[^\w\-_.]", "_", s)

def integrate_cve_to_qualys(days_back: int = DAYS_BACK):
    logger.info("Starting integrated CVE→Qualys workflow (last %d days)...", days_back)

    ensure_audit_folder_exists()
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    applications = load_applications()

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

        # 1) Fetch CVEs
        matched, clubbed = fetch_recent_cves(product, days_back=days_back)
        combined = matched + clubbed
        logger.info("  Found %d CVEs for %s", len(combined), product)

        # 2) Save audit log
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = sanitize_filename(product.lower())
        log_path = os.path.join(AUDIT_LOG_FOLDER, f"{safe_name}_cve_{ts}.json")
        save_audit_log(combined, custom_path=log_path)
        logger.info("  Audit log saved → %s", log_path)

        # 3) Extract CVE info
        cve_ids       = [c["cve_id"]  for c in combined]
        cve_summaries = [c["summary"] for c in combined]
        versions = sorted({
            c["version"].strip()
            for c in combined
            if c.get("version") and c["version"] != "Unknown"
        })

        if not versions:
            logger.info("  No valid versions for %s; skipping Qualys.", product)
            continue

        try:
            logger.info("  Running Qualys for versions: %s", versions)
            qs.run(product, versions)

            # ✅ Save as Assets_<software>_<timestamp>.xlsx
            excel_name = os.path.join(
                OUTPUT_FOLDER,
                f"Assets_{sanitize_filename(product)}_{ts}.xlsx"
            )

            # ✅ Send email with that Excel file
            qs.send_email(
                filename=excel_name,
                software_name=product,
                max_versions=versions,
                cve_ids=cve_ids,
                cve_summaries=cve_summaries
            )
        except Exception as e:
            logger.error("  Error during Qualys run or email for %s: %s", product, e)

        if idx < len(applications):
            logger.info("Sleeping %d seconds to respect rate limits...", RATE_LIMIT_DELAY)
            time.sleep(RATE_LIMIT_DELAY)

    logger.info("Integration complete.")

if __name__ == "__main__":
    integrate_cve_to_qualys()
