import argparse
import sys
import os
from core.parser import ApexParser
from core.scorer import ApexRiskScorer
from reports.pdf_generator import ApexPDFGenerator

# ANSI Color Codes for Kali Terminal
RED = "\033[91m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_banner():
    banner = f"""{RED}{BOLD}
    █████╗ ██████╗ ███████╗██╗  ██╗
   ██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝
   ███████║██████╔╝█████╗   ╚███╔╝ 
   ██╔══██║██╔═══╝ ██╔══╝   ██╔██╗ 
   ██║  ██║██║     ███████╗██╔╝ ██╗
   ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝{RESET}
   {BOLD}APEX - Automated Phishing Executive Examiner{RESET}
   {YELLOW}Enterprise Email Forensics & SOC Triage Engine{RESET}
   --------------------------------------------------
    """
    print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="APEX: Automated Phishing Executive Examiner")
    parser.add_argument("-f", "--file", required=True, help="Path to the email sample file (.eml or .msg)")
    parser.add_argument("-o", "--output", default="reports_output", help="Output directory for PDF reports")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"{RED}[!] Error: File not found -> {args.file}{RESET}")
        sys.exit(1)
    
    print(f"{CYAN}[*]{RESET} Ingesting and parsing email evidence: {BOLD}{args.file}{RESET}")
    email_parser = ApexParser(args.file)
    parsed_data = email_parser.parse()
    
    print(f"{CYAN}[*]{RESET} Computing phishing risk score and threat tier...")
    scorer = ApexRiskScorer(parsed_data)
    risk_data = scorer.evaluate()
    parsed_data.update(risk_data)
    
    print(f"{CYAN}[*]{RESET} Generating executive PDF forensic report...")
    pdf_gen = ApexPDFGenerator(parsed_data, output_dir=args.output)
    report_path = pdf_gen.build_pdf()
    
    score = parsed_data.get('risk_score', 0)
    severity = parsed_data.get('severity', 'LOW')
    color = GREEN if score < 40 else YELLOW if score < 75 else RED
    
    print(f"\n{color}{BOLD}[+] INVESTIGATION COMPLETE!{RESET}")
    print(f"    - Risk Score: {color}{BOLD}{score}/100 ({severity}){RESET}")
    print(f"    - Report Saved: {BOLD}{report_path}{RESET}\n")

if __name__ == "__main__":
    main()
