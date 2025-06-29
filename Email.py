import os
import logging
from datetime import datetime
import win32com.client as win32

logger = logging.getLogger(__name__)

class QualysSearcher:
    # … your existing init, run(), collect_results() …

    def send_email(
        self,
        filename: str,
        cve_ids: list[str],
        vulnerable_count: int,
        total_detections: int,
        cve_summaries: list[str] | None = None
    ):
        """
        Send email notification via Outlook draft.
        
        Parameters:
          - filename: path to the attached report
          - cve_ids: list of CVE IDs, e.g. ["CVE-2025-1234", "CVE-2025-5678"]
          - vulnerable_count: number of vulnerable hosts found
          - total_detections: total vulnerabilities detected across all hosts
          - cve_summaries: optional list of summary strings; must be same length as cve_ids
        """
        if vulnerable_count <= 0:
            logger.info("No vulnerable hosts found - no email drafted.")
            return

        # Try to create Outlook draft
        try:
            outlook = win32.Dispatch("Outlook.Application")
        except Exception as e:
            logger.error(f"Failed to dispatch Outlook.Application: {e}")
            return

        mail = outlook.CreateItem(0)
        cve_list = ", ".join(cve_ids)
        mail.Subject = f"[VULNERABILITY ALERT] {vulnerable_count} Vulnerable Hosts - CVE(s): {cve_list}"

        # Build the optional summaries section
        if cve_summaries:
            # Ensure our lists line up
            lines = []
            for cve_id, summary in zip(cve_ids, cve_summaries):
                lines.append(f"- {cve_id}: {summary}")
            summaries_block = "\nSummaries:\n" + "\n".join(lines) + "\n"
        else:
            summaries_block = ""

        mail.Body = f"""
Hello,

Vulnerability scan results for CVE(s): {cve_list}

{summaries_block}Statistics:
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

        # Attach the report
        try:
            abs_path = os.path.abspath(filename)
            mail.Attachments.Add(abs_path)
        except Exception as e:
            logger.error(f"Failed to attach file {filename}: {e}")

        mail.Display()
        logger.info(f"Email draft created for {vulnerable_count} vulnerable hosts.")
