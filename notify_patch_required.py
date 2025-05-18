import pandas as pd
import win32com.client as win32
import datetime
import os

def normalize_version(version):
    return int(''.join(version.split('.')))

def find_older_versions(csv_path, app_name, current_version):
    df = pd.read_csv(csv_path)
    current_ver_num = normalize_version(current_version)

    df_filtered = df[df['Application'].str.lower() == app_name.lower()].copy()
    df_filtered['VersionNum'] = df_filtered['Version'].apply(normalize_version)

    outdated_df = df_filtered[df_filtered['VersionNum'] < current_ver_num]
    return outdated_df.drop(columns=['VersionNum'])

def log_audit(app_name, version, count, log_file="audit_log.csv"):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    row = pd.DataFrame([{
        'Timestamp': now,
        'Application': app_name,
        'Checked Version': version,
        'Outdated Devices Found': count
    }])

    if os.path.exists(log_file):
        row.to_csv(log_file, mode='a', index=False, header=False)
    else:
        row.to_csv(log_file, index=False, header=True)

def generate_email(app_name, current_version, outdated_df, attach_path=None):
    outlook = win32.Dispatch("Outlook.Application")
    mail = outlook.CreateItem(0)
    mail.Subject = f"[Action Required] Patch outdated {app_name} installations"

    header = f"""
    <p>Dear IT Team,</p>
    <p>The following devices have <b>{app_name}</b> installed with a version older than <b>{current_version}</b>.</p>
    <p>Please patch them to the latest version as soon as possible:</p>
    """

    table_html = outdated_df.to_html(index=False, border=1)
    footer = """
    <p>Regards,<br>Your Friendly Patch Monitor Bot 🤖</p>
    """

    mail.HTMLBody = header + table_html + footer

    if attach_path and os.path.exists(attach_path):
        mail.Attachments.Add(Source=os.path.abspath(attach_path))

    mail.Display()

if __name__ == "__main__":
    csv_file = "Application.csv"
    log_file = "audit_log.csv"

    print("🔍 Patch Monitoring Interface")
    app_name = input("Enter Application Name (e.g., Adobe Photoshop): ").strip()
    current_version = input("Enter Current Version (e.g., 25.3): ").strip()

    outdated_devices = find_older_versions(csv_file, app_name, current_version)

    if outdated_devices.empty:
        print("\n✅ All devices are up to date.")
    else:
        print(f"\n🚨 Found {len(outdated_devices)} outdated devices. Generating email draft...")

        output_path = f"{app_name.replace(' ', '_')}_outdated_devices.csv"
        outdated_devices.to_csv(output_path, index=False)

        log_audit(app_name, current_version, len(outdated_devices), log_file)

        generate_email(app_name, current_version, outdated_devices, attach_path=output_path)
