RECAPTURE v1.0 - Forensic Triage Tool
-------------------------------------
Release: Gold Master (v1.0)
Date:    January 2026

DESCRIPTION
-----------
Recapture is a standalone forensic triage tool designed for rapid on-site 
analysis and evidence verification. It allows investigators to identify 
files, verify integrity via hashing, search for keywords, and detect 
forensic artefacts without requiring software installation.

This Gold Master release focuses on stability, integrity validation, and 
ease of use for first responders and analysts.

KEY FEATURES
------------
* Zero-Installation: Runs directly from a USB stick (Portable).
* Validation Counters: automatically tallies Total Files & Folders 
  processed to support chain of custody verification.
* Format Support: 
  - Physical Drives & Local Folders
  - E01 Forensic Images (EnCase)
  - Raw Images (DD/IMG)
* Analysis Capabilities:
  - MD5 & SHA-1 Hashing
  - Signature Analysis (Header vs Extension Mismatch detection)
  - Live Keyword Searching
  - Deleted File Identification
* Reporting: 
  - Generates self-contained, navigable HTML reports.
  - Interactive Legend built into the GUI for report interpretation.

USAGE
-----
1. GUI MODE (Graphical Interface):
   Double-click "Recapture_GUI_v1.0.exe".
   - Select your target (Folder or Image file).
   - (Optional) Load a hash list or keywords.
   - Click "Start Scan".
   - Use the "Help / Legend" button to understand report icons.

2. CLI MODE (Command Line):
   Double-click "Recapture_CLI_v1.0.exe" for interactive mode.
   OR run via command prompt for scripting:
   
   Recapture_CLI_v1.0.exe [Target_Path] --output [Report_Dir] --skip-hash

SYSTEM REQUIREMENTS
-------------------
* OS: Windows 10 or Windows 11 (64-bit).
* RAM: 4GB minimum (8GB recommended for large images).
* Admin Rights: Recommended for accessing physical drives.

DISCLAIMER
----------
This tool is designed for triage and preliminary analysis. While Recapture 
utilises industry-standard libraries (SleuthKit/TSK), all findings should 
be verified with a validated forensic suite.