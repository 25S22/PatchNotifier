# Qualys Patch Management System - Standard Operating Procedure

## Table of Contents

1. [Document Information](#1-document-information)
2. [System Overview](#2-system-overview)
3. [Roles and Responsibilities](#3-roles-and-responsibilities)
4. [System Architecture and Configuration](#4-system-architecture-and-configuration)
5. [Installation and Setup Procedures](#5-installation-and-setup-procedures)
6. [Operating Procedures](#6-operating-procedures)
7. [Output Analysis and Reporting](#7-output-analysis-and-reporting)
8. [CVE Monitoring and Automated Response](#8-cve-monitoring-and-automated-response)
9. [Troubleshooting and Error Resolution](#9-troubleshooting-and-error-resolution)
10. [Security and Compliance](#10-security-and-compliance)
11. [Maintenance and Support](#11-maintenance-and-support)

---

## 1. Document Information

**Document Title:** Qualys Patch Management System - Standard Operating Procedure  
**Version:** 2.0  
**Effective Date:** [Insert Date]  
**Review Cycle:** Annual  
**Document Owner:** IT Security Manager  
**Approved By:** Chief Information Security Officer  

### 1.1 Document Control

| Version | Date | Author | Changes |
|---------|------|---------|---------|
| 1.0 | [Date] | [Author] | Initial document creation |
| 2.0 | [Date] | [Author] | Updated for current system implementation |

---

## 2. System Overview

### 2.1 Purpose
This Standard Operating Procedure provides comprehensive instructions for operating the Qualys-based patch management system that automates vulnerability detection, asset inventory, and patch status reporting for enterprise software applications.

### 2.2 System Components
The patch management system consists of the following integrated components:

- **Qualys Asset Management API**: Primary interface for querying installed software across enterprise assets
- **NIST NVD Integration**: Real-time monitoring of high and critical Common Vulnerabilities and Exposures (CVEs)
- **Application JSON Database**: Centralized inventory of critical enterprise software requiring monitoring
- **Microsoft Outlook Integration**: Automated email notification system for stakeholder alerts
- **Excel Report Generation**: Comprehensive patch status reports with categorized analysis

### 2.3 Key Capabilities
- Multi-version range support for complex software distributions (e.g., Apache Tomcat with multiple active branches)
- Automated CVE monitoring with severity-based alerting (CVSS ≥ 7.0)
- Real-time asset inventory with patch compliance status
- Automated email notifications with statistical summaries
- Excel report generation with detailed asset categorization

### 2.4 Business Objectives
- Maintain enterprise security posture through timely vulnerability remediation
- Ensure compliance with organizational security policies and regulatory requirements
- Minimize business disruption through structured patch deployment processes
- Provide comprehensive visibility into patch compliance across the enterprise

---

## 3. Roles and Responsibilities

### 3.1 IT Security Team
**Primary Accountability:** System operation, vulnerability analysis, and coordination

**Responsibilities:**
- Execute daily system operations and monitoring
- Analyze vulnerability reports and prioritize remediation activities
- Coordinate with development and operations teams for patch deployment
- Maintain the application JSON database with current software inventory
- Generate compliance reports for management review

### 3.2 System Administrator
**Primary Accountability:** Technical system maintenance and configuration

**Responsibilities:**
- Install, configure, and maintain the patch management system
- Manage Qualys API credentials and SSL certificates
- Monitor system performance and troubleshoot technical issues
- Implement system updates and security patches
- Maintain backup and recovery procedures

### 3.3 Development Teams
**Primary Accountability:** Application-level vulnerability remediation

**Responsibilities:**
- Review vulnerability reports for assigned applications
- Develop and test application patches and updates
- Coordinate with security team on remediation timelines
- Implement secure coding practices to prevent future vulnerabilities

### 3.4 Operations Teams
**Primary Accountability:** Infrastructure patch deployment and system availability

**Responsibilities:**
- Execute approved patch deployments according to change management procedures
- Monitor system availability during patching windows
- Implement rollback procedures when necessary
- Maintain production system stability and performance

---

## 4. System Architecture and Configuration

### 4.1 Technical Architecture

**API Integration Workflow:**
1. **Authentication Phase**: Secure login to Qualys API using corporate credentials
2. **Asset Discovery**: Query enterprise assets for specific software installations
3. **Version Analysis**: Compare installed versions against target patch levels using semantic versioning
4. **Report Generation**: Create categorized Excel reports with compliance status
5. **Notification Distribution**: Send automated email alerts with summary statistics
6. **Session Management**: Secure logout and session cleanup

### 4.2 API Configuration Parameters

**Primary Endpoints:**
- **Base URL**: `https://qualysapi.qg1.apps.qualys.in`
- **Session Management**: `/api/2.0/fo/session/`
- **Asset Search**: `/qps/rest/2.0/search/am/hostasset`

**Required Authentication:**
- **Username**: Qualys API service account with read permissions
- **Password**: Corresponding service account password
- **SSL Certificate**: Corporate certificate for API authentication (`/path/to/your/corporate_cert.pem`)

### 4.3 System Dependencies

**Python Environment Requirements:**
```python
# Core dependencies
requests>=2.28.0
xml.etree.ElementTree
pandas>=1.5.0
packaging>=21.0
logging
win32com.client  # Microsoft Outlook integration
```

**Infrastructure Requirements:**
- Network connectivity to Qualys cloud platform
- Microsoft Outlook installation for email automation
- Secure file storage for SSL certificates and reports
- Administrative access to target systems for verification

---

## 5. Installation and Setup Procedures

### 5.1 Pre-Installation Requirements

**System Prerequisites:**
- Python 3.8 or higher installed
- Network access to Qualys API endpoints
- Microsoft Outlook configured with appropriate email account
- SSL certificate obtained from IT Security team

**Security Requirements:**
- Service account credentials with appropriate Qualys permissions
- SSL certificate with valid chain of trust
- Secure storage location for sensitive configuration files

### 5.2 Configuration Process

**Step 1: Update Configuration Parameters**
```python
# === CONFIGURATION SECTION ===
USERNAME        = "your_qualys_username"          # Replace with service account
PASSWORD        = "your_qualys_password"          # Replace with service account password
CERT_PATH       = "/path/to/your/corporate_cert.pem"  # Update certificate path
BASE_URL        = "https://qualysapi.qg1.apps.qualys.in"  # Verify correct region
PAGE_SIZE       = 100                             # Adjust based on performance
FILTER_OPERATOR = "CONTAINS"                      # Search operator
LOG_LEVEL       = logging.INFO                    # Logging verbosity
```

**Step 2: Certificate Installation**
1. Obtain corporate SSL certificate from IT Security team
2. Place certificate in secure directory with restricted access permissions
3. Update `CERT_PATH` variable with absolute path to certificate file
4. Verify certificate validity and expiration date

**Step 3: Application JSON Database Setup**
Configure the application inventory database with monitored software:
- Software names and version variants
- Target version requirements
- Business criticality classifications
- Responsible team assignments

### 5.3 Validation Testing

**System Verification Steps:**
1. Execute test authentication to Qualys API
2. Perform sample asset query with known software
3. Verify Excel report generation functionality
4. Test email notification system
5. Confirm logging and error handling

---

## 6. Operating Procedures

### 6.1 Standard Operation Workflow

**System Execution Process:**
1. **Launch Application**: Execute `python qualys_patch_scanner.py`
2. **Input Specification**: Provide software name and target version(s)
3. **Processing Monitoring**: Review progress indicators and status updates
4. **Result Analysis**: Examine generated Excel reports and email notifications
5. **Action Implementation**: Coordinate remediation activities based on results

### 6.2 Single Version Search Protocol

**Use Case:** Software with single target version requirement

**Input Format:**
```
Software Name: "Apache HTTP Server"
Target Version: "2.4.54"
```

**Processing Logic:**
- All devices with versions below 2.4.54 are categorized as "Below target"
- Devices meeting or exceeding version 2.4.54 are marked as "Up-to-date"
- Assets without the software are classified as "Not Found"

### 6.3 Multi-Version Range Search Protocol

**Use Case:** Software with multiple active support branches (e.g., Apache Tomcat)

**Input Format:**
```
Software Name: "Apache Tomcat"
Target Versions: "9.0.106/10.1.42/11.0.8"
```

**Processing Logic:**
- **Range 1**: 9.0.0 - 9.0.106 (Major.Minor: 9.0)
- **Range 2**: 10.1.0 - 10.1.42 (Major.Minor: 10.1)
- **Range 3**: 11.0.0 - 11.0.8 (Major.Minor: 11.0)

**⚠️ CRITICAL WARNING**: This approach excludes intermediate version ranges (e.g., 10.0.0-10.1.0). These older versions require separate searches and should be prioritized for immediate patching due to increased security risk.

### 6.4 Monitoring and Progress Tracking

**System Monitoring Indicators:**
- **Authentication Status**: Successful login confirmation
- **Page Processing**: Real-time updates for API pagination
- **Asset Processing**: Progress updates every 100 processed hosts
- **Error Handling**: Immediate notification of processing failures

---

## 7. Output Analysis and Reporting

### 7.1 Excel Report Structure

**Report Naming Convention:** `{software_name}_versions_{versions}.xlsx`

**Column Definitions:**

| Column | Description | Data Type |
|--------|-------------|-----------|
| Host ID | Qualys unique identifier for the asset | Numeric |
| DNS | DNS hostname of the asset | Text |
| NetBIOS | NetBIOS name of the asset | Text |
| Software | Actual software name detected on asset | Text |
| Version | Installed version number | Text |
| Status | Patch compliance status | Categorical |
| Range | Applicable version range for multi-version searches | Text |

### 7.2 Status Classification System

**Compliance Categories:**
- **Below target**: Asset requires patching - represents security risk
- **Up-to-date**: Asset meets minimum version requirements
- **Not Found**: Software not detected on asset (may be uninstalled or misconfigured)

### 7.3 Email Notification Format

**Automated Email Structure:**
- **Subject Line**: `[PATCH ALERT] {Software} – Versions ≤ {Target_Versions}`
- **Summary Statistics**: Total devices, below target count, up-to-date count, not found count
- **CVE Information**: Relevant vulnerability details when triggered by CVE monitoring
- **Action Items**: Clear remediation instructions for responsible teams
- **Attachments**: Generated Excel report with detailed findings

---

## 8. CVE Monitoring and Automated Response

### 8.1 NIST NVD Integration

**Monitoring Parameters:**
- **High Severity CVEs**: CVSS Base Score ≥ 7.0
- **Critical Severity CVEs**: CVSS Base Score ≥ 9.0
- **Scope**: CVEs affecting software in the application JSON database

**Automated Response Workflow:**
1. **Detection**: System identifies new high/critical CVEs
2. **Assessment**: Automatic matching against monitored software inventory
3. **Investigation**: Triggered Qualys asset searches for affected software
4. **Categorization**: Analysis of affected devices with compliance status
5. **Notification**: Priority email alerts to security and operations teams
6. **Tracking**: Integration with incident management systems

### 8.2 Application JSON Database Management

**Database Components:**
- **Software Inventory**: Complete list of monitored applications and versions
- **Version Tracking**: Current and target version requirements
- **Business Classifications**: Criticality ratings and impact assessments
- **Team Assignments**: Responsible contacts and escalation procedures

**Maintenance Requirements:**
- Monthly review and update of software inventory
- Quarterly validation of version requirements
- Annual assessment of business criticality ratings

---

## 9. Troubleshooting and Error Resolution

### 9.1 Common Issues and Resolutions

**Authentication Failures:**
- **Symptoms**: 403 Forbidden errors, login failures
- **Resolution Steps**:
  1. Verify username and password credentials
  2. Check SSL certificate path and file permissions
  3. Confirm API access permissions in Qualys console
  4. Validate certificate expiration and chain of trust

**Empty or Incomplete Results:**
- **Symptoms**: No assets returned, missing expected devices
- **Resolution Steps**:
  1. Verify software name spelling and capitalization
  2. Confirm assets exist in Qualys inventory
  3. Check software installation on targeted assets
  4. Review search filters and parameters

**Performance Issues:**
- **Symptoms**: Timeouts, slow response times
- **Resolution Steps**:
  1. Reduce PAGE_SIZE parameter for smaller batch processing
  2. Increase LOG_LEVEL for detailed debugging information
  3. Verify network connectivity and latency to Qualys API
  4. Check system resource utilization

### 9.2 Error Code Reference

**HTTP Error Codes:**
- **403 Forbidden**: Insufficient API permissions or credential issues
- **500 Internal Server Error**: Qualys platform issues or malformed requests
- **XML Parse Error**: Invalid response format from Qualys API

**Resolution Protocol:**
1. Log all error details with timestamps
2. Implement retry logic with exponential backoff
3. Escalate persistent issues to Qualys support
4. Document resolutions for future reference

---

## 10. Security and Compliance

### 10.1 Credential Management

**Security Requirements:**
- Store credentials using secure methods (environment variables, encrypted storage)
- Implement regular credential rotation (quarterly minimum)
- Use dedicated service accounts with principle of least privilege
- Monitor credential usage and access patterns

**Access Control:**
- Restrict system access to authorized personnel only
- Implement multi-factor authentication where possible
- Maintain audit logs of all system access
- Regular review of user permissions and access rights

### 10.2 Data Protection

**Sensitive Data Handling:**
- Excel reports contain confidential asset information
- Implement proper data classification and handling procedures
- Use encrypted channels for report transmission
- Maintain secure storage with appropriate retention policies

**Certificate Management:**
- Monitor SSL certificate expiration dates
- Implement automated certificate renewal processes
- Maintain secure storage of certificate files
- Regular validation of certificate chain integrity

### 10.3 Compliance Requirements

**Audit Documentation:**
- All system operations are logged with timestamps
- Email notifications provide comprehensive audit trail
- Excel reports serve as compliance evidence
- Retention policies align with regulatory requirements

**Metrics and Reporting:**
- Monthly patch compliance reports
- Quarterly vulnerability trend analysis
- Annual security posture assessments
- Regulatory compliance documentation

---

## 11. Maintenance and Support

### 11.1 Regular Maintenance Tasks

**Monthly Tasks:**
- Review and update application JSON database
- Validate system performance metrics
- Check SSL certificate expiration dates
- Review error logs and system alerts

**Quarterly Tasks:**
- Audit API credentials and permissions
- Update Python dependencies and libraries
- Review and test backup and recovery procedures
- Validate compliance with security policies

**Annual Tasks:**
- Comprehensive security assessment
- Update SSL certificates and security configurations
- Review and update this SOP document
- Conduct disaster recovery testing

### 11.2 Support and Escalation

**Technical Support Contacts:**
- **Primary Support**: IT Security Team
- **System Issues**: System Administrator
- **API Problems**: Qualys Technical Support
- **Critical Issues**: Chief Information Security Officer

**Escalation Procedures:**
- **High/Critical CVEs**: Immediate notification to security leadership (within 1 hour)
- **System Failures**: Alert infrastructure team within 4 hours
- **Compliance Issues**: Notify risk management team within 24 hours
- **Data Breaches**: Follow incident response procedures immediately

### 11.3 Performance Monitoring

**Key Performance Indicators:**
- System availability percentage
- API response times
- Report generation success rates
- Email notification delivery rates
- CVE detection and response times

**Monitoring Thresholds:**
- API response time > 30 seconds requires investigation
- System availability < 95% requires immediate attention
- Failed report generation requires escalation
- CVE response time > 4 hours requires management notification

---

## 12. Document Control and Approval

**Document Classification:** Internal Use Only  
**Security Classification:** Confidential  
**Distribution:** IT Security Team, System Administrators, Operations Teams  

**Review and Approval:**
- **Technical Review**: Senior System Administrator
- **Security Review**: IT Security Manager  
- **Final Approval**: Chief Information Security Officer

**Change Management:**
- All changes require formal change request
- Impact assessment required for major modifications
- Testing and validation required before implementation
- Stakeholder notification for all changes

---

**END OF DOCUMENT**

*This SOP is proprietary and confidential. Distribution is restricted to authorized personnel only.*
