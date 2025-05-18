# 🔧 PatchNotifier

PatchNotifier is a simple Python utility that scans a CSV inventory of applications and devices, identifies outdated versions, and automatically drafts an email in Microsoft Outlook listing the devices that need patching.

---

## 🚀 Features

- Accepts an input dataset (CSV) of devices, applications, and their versions.
- Compares the application version against the latest provided version.
- Identifies all devices running older versions.
- Generates a CSV report of outdated devices.
- Auto-creates an Outlook email draft with the report attached and a pre-written message — ready to send.

---

## 🗂️ Input Format

The input `devices.csv` file should have the following columns:

| Application      | DeviceID     | Version   | Last Modified       |
|------------------|--------------|-----------|----------------------|
| Google Chrome    | LAPTOP-001   | 117.0.2   | 2025-05-10 12:00:00  |
| Adobe Photoshop  | LAPTOP-002   | 8.0.5     | 2025-05-16 08:30:00  |

---

## ⚙️ Setup Instructions

### 1. Clone or Download

```bash
git clone https://github.com/yourusername/PatchNotifier.git
cd PatchNotifier
