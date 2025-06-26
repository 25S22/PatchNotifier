# qualys.py (excerpt)

import os
import logging
from datetime import datetime
import win32com.client as win32

logger = logging.getLogger(__name__)

class QualysSearcher:
    # … your existing init, run(), collect_results() …

    def send_email(self, filename, cve_ids, cve_summaries, vulnerable_count, total_detections):
        """
        Send email notification via Outlook draft, now including CVE summaries.
        """
        if vulnerable_count <= 0:
            logger.info("No vulnerable hosts found - no email drafted.")
            return

        try:
            outlook = win32.Dispatch("Outlook.Application")
        except Exception as e:
            logger.error(f"Failed to dispatch Outlook.Application: {e}")
            return

        mail = outlook.CreateItem(0)
        cve_list = ", ".join(cve_ids)

        # Build a bullet list of CVE summaries
        summary_lines = "\n".join(
            f"- {cve_id}: {summary}"
            for cve_id, summary in zip(cve_ids, cve_summaries)
        )

        mail.Subject = f"[VULNERABILITY ALERT] {vulnerable_count} Vulnerable Hosts - CVE(s): {cve_list}"
        mail.Body = f"""
Hello,

Vulnerability scan results for CVE(s): {cve_list}

Summaries:
{summary_lines}

Statistics:
- Total vulnerable hosts found: {vulnerable_count}
- Total vulnerability detections: {total_detections}

Please find attached the detailed vulnerability report.

IMMEDIATE ACTION REQUIRED:
- Review all affected systems
- Prioritize patching based on severity levels
- Verify patch deployment after remediation

Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Regards,
Vulnerability Management System
""".strip()

        try:
            abs_path = os.path.abspath(filename)
            mail.Attachments.Add(abs_path)
        except Exception as e:
            logger.error(f"Failed to attach file {filename}: {e}")

        mail.Display()
        logger.info(f"Email draft created for {vulnerable_count} vulnerable hosts.")
