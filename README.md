# VulnPatrol — OpenVAS Vulnerability Management Tool 📃

You can automate vulnerability scans, add custom signatures, and send scan logs to a SIEM system like Splunk with this repository's OpenVAS vulnerability management system, which is Python-based.

## Features
- Connect and authenticate with OpenVAS to perform vulnerability scans.
- Create and start scan tasks for specified targets.
- Fetch scan reports in XML format.
- Add custom NVT (Network Vulnerability Test) scripts to OpenVAS.
- Log scan activities and results to Splunk using its HTTP Event Collector (HEC).

## Prerequisites

Before using this project, make sure you have the following:
- An operational **OpenVAS** instance.
- Python 3.6 or higher.
- **Splunk** (optional) for logging scan results.

## Setup

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/vulnPatrol.git
cd vulnPatrol
