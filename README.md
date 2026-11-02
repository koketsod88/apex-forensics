# APEX (Automated Phishing Executive Examiner)

> **Automated Email Forensics & Executive PDF Reporting Engine**

APEX is an open-source, CLI-driven forensic engine built to streamline phishing incident response, automate header and body IOC parsing, and produce publication-grade executive PDF reports for SOC analysts and C-suite stakeholders.

---

## Key Features

- **Automated Header & Hop Parsing**: Extracts routing chains, `Return-Path`, `From`, `Message-ID`, and authentication headers (`SPF`, `DKIM`, `DMARC`).
- **Defanged IOC Extraction**: Automatically extracts and sanitizes embedded URLs and IP addresses to prevent accidental clicks.
- **Payload & Attachment Hashing**: Computes SHA-256 and MD5 hashes for inline attachments and suspicious payloads.
- **Weighted Threat Scoring**: Evaluates header mismatches, defanged links, and attachment signatures to calculate a composite score ($0 - 100$) mapped to severity tiers (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Executive PDF Generation**: Generates structured, multi-page C-level PDF summary reports via ReportLab with threat indicators and SOC remediation playbooks.
- **Privacy-First Design**: Operates entirely offline on local raw `.eml` files—no external data leakage.

---

## Installation

### Prerequisites
- Python 3.9+
- Linux / macOS / WSL (Tested on Kali Linux)

### Setup

1. **Clone the repository**:
   ```bash
   git clone [https://github.com/koketsod88/apex-forensics.git](https://github.com/koketsod88/apex-forensics.git)
   cd apex-forensics
   ```

2. **Create and activate virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage Guide

### Basic Forensic Analysis
To analyze a raw email (`.eml`) file and generate an executive PDF report:

```bash
python3 apex.py -f path/to/target.eml
```

### Specifying Custom Output Directories
To save the generated PDF report to a custom directory:

```bash
python3 apex.py -f path/to/target.eml -o /path/to/output_folder/
```

### CLI Help
To view all available command-line options:

```bash
python3 apex.py --help
```

---

## Output Structure

Generated reports are automatically stored in `./reports_output/` with timestamped naming conventions:

```text
apex-forensics/
├── core/                  # Parser and scoring modules
├── reports/               # ReportLab PDF styling & layout engines
├── reports_output/        # Output directory for generated PDF reports (Ignored by Git)
├── apex.py                # Main CLI entry point
├── README.md              # Project documentation
└── requirements.txt       # Python dependencies
```

---

## Operational Privacy

All forensic parsing and report generation occur strictly on your local machine. No analyzed email artifacts, headers, or generated PDF reports are transmitted externally or tracked in version control.

---

## License

This project is licensed under the [MIT License](LICENSE).
