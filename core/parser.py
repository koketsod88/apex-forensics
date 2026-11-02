import os
import io
import re
import hashlib
import mailparser
import extract_msg
from core.hop_tracer import ApexHopTracer
from core.yara_scanner import ApexYaraScanner

class ApexParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.ext = os.path.splitext(filepath)[1].lower()
        self.yara_scanner = ApexYaraScanner()

    def parse(self):
        """Unified parser handling .eml and .msg files with deep forensic extraction (zero-disk leakage)."""
        raw_bytes, file_hashes = self._load_into_memory()
        
        if self.ext == '.msg':
            data = self._parse_msg_stream(raw_bytes)
        else:
            data = self._parse_eml_stream(raw_bytes)
            
        data['hashes'] = file_hashes
        
        # Routing hop tracing
        tracer = ApexHopTracer(data.get('headers'))
        data['routing_hops'] = tracer.trace_hops()
        
        # Advanced Forensic Enhancements
        data['urls'] = self._extract_and_defang_urls(data.get('body', ''))
        data['authentication'] = self._check_email_authentication(data.get('headers', ''))
        
        return data

    def parse_email(self):
        return self.parse()

    def _load_into_memory(self):
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        
        try:
            with open(self.filepath, "rb") as f:
                raw_bytes = f.read()
                
            sha256_hash.update(raw_bytes)
            md5_hash.update(raw_bytes)
            
            file_hashes = {
                "sha256": sha256_hash.hexdigest(),
                "md5": md5_hash.hexdigest()
            }
            return raw_bytes, file_hashes
        except Exception as e:
            return b"", {
                "sha256": "ERROR_COMPUTING_HASH",
                "md5": "ERROR_COMPUTING_HASH"
            }

    def _extract_and_defang_urls(self, body_text):
        """Extracts URLs and defangs them (e.g., hxxp://) to safely display in forensic reports."""
        if not body_text:
            return []
        
        url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        found_urls = url_pattern.findall(str(body_text))
        
        defanged_list = []
        for url in set(found_urls):
            defanged = url.replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')
            defanged_list.append({
                "original": url,
                "defanged": defanged
            })
        return defanged_list

    def _check_email_authentication(self, headers):
        """Analyzes transport headers for SPF, DKIM, and DMARC authentication results."""
        auth_results = {
            "spf": "NOT_FOUND",
            "dkim": "NOT_FOUND",
            "dmarc": "NOT_FOUND"
        }
        
        header_str = ""
        if isinstance(headers, list):
            header_str = "\n".join([f"{k}: {v}" for k, v in headers])
        else:
            header_str = str(headers)
            
        header_lower = header_str.lower()
        
        if "spf=pass" in header_lower or "received-spf: pass" in header_lower:
            auth_results["spf"] = "PASS"
        elif "spf=fail" in header_lower or "received-spf: fail" in header_lower:
            auth_results["spf"] = "FAIL"
            
        if "dkim=pass" in header_lower:
            auth_results["dkim"] = "PASS"
        elif "dkim=fail" in header_lower:
            auth_results["dkim"] = "FAIL"
            
        if "dmarc=pass" in header_lower:
            auth_results["dmarc"] = "PASS"
        elif "dmarc=fail" in header_lower or "dmarc=permerror" in header_lower:
            auth_results["dmarc"] = "FAIL"
            
        return auth_results

    def _parse_eml_stream(self, raw_bytes):
        mail = mailparser.parse_from_bytes(raw_bytes)
        
        sender = ""
        if mail.from_:
            if isinstance(mail.from_, list) and len(mail.from_) > 0:
                if isinstance(mail.from_[0], (list, tuple)) and len(mail.from_[0]) > 1:
                    sender = mail.from_[0][1]
                else:
                    sender = str(mail.from_[0])
            else:
                sender = str(mail.from_)
        
        if not sender and mail.mail_header:
            for k, v in mail.mail_header:
                if k.lower() == 'from':
                    sender = v
                    break

        to_field = mail.to if mail.to else ""
        if isinstance(to_field, list):
            to_field = ", ".join([str(t[1] if isinstance(t, (list, tuple)) and len(t) > 1 else t) for t in to_field])
        
        if not to_field and mail.mail_header:
            for k, v in mail.mail_header:
                if k.lower() == 'to':
                    to_field = v
                    break

        attachments = []
        if mail.attachments:
            for att in mail.attachments:
                fname = att.get('filename', 'unknown')
                payload = att.get('payload', '')
                if isinstance(payload, str):
                    payload_bytes = payload.encode('utf-8', errors='ignore')
                else:
                    payload_bytes = payload
                
                att_sha256 = hashlib.sha256(payload_bytes).hexdigest()
                ext = os.path.splitext(fname)[1].lower()
                is_exec = ext in ['.exe', '.bat', '.cmd', '.scr', '.pif', '.js', '.vbs']
                
                attachments.append({
                    "filename": fname,
                    "sha256": att_sha256,
                    "is_executable": is_exec,
                    "size": len(payload_bytes)
                })

        return {
            "subject": mail.subject or "No Subject",
            "from": sender or "Unknown Sender",
            "sender": sender or "Unknown Sender",
            "to": to_field or "Unknown Recipient",
            "recipient": to_field or "Unknown Recipient",
            "date": mail.date,
            "body": mail.body,
            "headers": mail.mail_header,
            "attachments": attachments
        }

    def _parse_msg_stream(self, raw_bytes):
        msg = extract_msg.Message(io.BytesIO(raw_bytes))
        
        sender = ""
        for attr in ['sender', 'author', 'sentRepresentingName', 'origSenderName', 'displayFrom']:
            val = getattr(msg, attr, None)
            if val and str(val).strip():
                sender = str(val).strip()
                break
        
        header_text = ""
        try:
            if hasattr(msg, 'header') and msg.header:
                header_text = str(msg.header)
        except Exception:
            pass

        if not sender and header_text:
            for line in header_text.splitlines():
                if line.lower().startswith('from:'):
                    sender = line.split(':', 1)[1].strip()
                    break

        if not sender:
            sender = "Unknown Sender"

        to_field = ""
        for attr in ['to', 'displayTo', 'sentRepresentingEmailAddress', 'recipients']:
            val = getattr(msg, attr, None)
            if val and str(val).strip():
                to_field = str(val).strip()
                break

        if not to_field and header_text:
            for line in header_text.splitlines():
                if line.lower().startswith('to:'):
                    to_field = line.split(':', 1)[1].strip()
                    break

        if not to_field:
            to_field = "Unknown Recipient"

        attachments = []
        if msg.attachments:
            for att in msg.attachments:
                fname = getattr(att, 'filename', 'unknown')
                data_bytes = getattr(att, 'data', b'')
                if not isinstance(data_bytes, bytes):
                    data_bytes = str(data_bytes).encode('utf-8', errors='ignore')
                
                att_sha256 = hashlib.sha256(data_bytes).hexdigest()
                ext = os.path.splitext(fname)[1].lower()
                is_exec = ext in ['.exe', '.bat', '.cmd', '.scr', '.pif', '.js', '.vbs']
                
                attachments.append({
                    "filename": fname,
                    "sha256": att_sha256,
                    "is_executable": is_exec,
                    "size": len(data_bytes)
                })
                
        parsed_data = {
            "subject": msg.subject or "No Subject",
            "from": sender,
            "sender": sender,
            "to": to_field,
            "recipient": to_field,
            "date": msg.date,
            "body": msg.body,
            "headers": header_text,
            "attachments": attachments
        }
        msg.close()
        return parsed_data
