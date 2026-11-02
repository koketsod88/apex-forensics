import os
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
        """Unified parser handling .eml and .msg files with hashes, hops, and YARA scans."""
        file_hashes = self._compute_evidence_hashes()
        
        if self.ext == '.msg':
            data = self._parse_msg()
        else:
            data = self._parse_eml()
            
        # Add chain-of-custody hashes
        data['hashes'] = file_hashes
        
        # Trace routing hops
        tracer = ApexHopTracer(data.get('headers'))
        data['routing_hops'] = tracer.trace_hops()
        
        return data

    def parse_email(self):
        """Alias for parse() to match main entrypoint expectations."""
        return self.parse()

    def _compute_evidence_hashes(self):
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        
        try:
            with open(self.filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
                    md5_hash.update(byte_block)
            return {
                "sha256": sha256_hash.hexdigest(),
                "md5": md5_hash.hexdigest()
            }
        except Exception as e:
            return {
                "sha256": "ERROR_COMPUTING_HASH",
                "md5": "ERROR_COMPUTING_HASH"
            }

    def _parse_eml(self):
        mail = mailparser.parse_from_file(self.filepath)
        return {
            "subject": mail.subject,
            "from": mail.from_[0][1] if mail.from_ else "",
            "to": mail.to,
            "date": mail.date,
            "body": mail.body,
            "headers": mail.mail_header,
            "attachments": [att['filename'] for att in mail.attachments] if mail.attachments else []
        }

    def _parse_msg(self):
        msg = extract_msg.Message(self.filepath)
        parsed_data = {
            "subject": msg.subject,
            "from": msg.sender,
            "to": msg.to,
            "date": msg.date,
            "body": msg.body,
            "headers": str(msg.header) if msg.header else "",
            "attachments": [att.filename for att in msg.attachments] if msg.attachments else []
        }
        msg.close()
        return parsed_data
