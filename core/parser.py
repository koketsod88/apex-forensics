import os
import io
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
        """Unified parser handling .eml and .msg files entirely via in-memory byte streams (zero-disk leakage)."""
        raw_bytes, file_hashes = self._load_into_memory()
        
        if self.ext == '.msg':
            data = self._parse_msg_stream(raw_bytes)
        else:
            data = self._parse_eml_stream(raw_bytes)
            
        data['hashes'] = file_hashes
        
        tracer = ApexHopTracer(data.get('headers'))
        data['routing_hops'] = tracer.trace_hops()
        
        return data

    def parse_email(self):
        return self.parse()

    def _load_into_memory(self):
        """Reads file into memory as bytes and computes cryptographic chain-of-custody hashes simultaneously."""
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

        to_field = mail.to if mail.to else ""
        if isinstance(to_field, list):
            to_field = ", ".join([str(t[1] if isinstance(t, (list, tuple)) and len(t) > 1 else t) for t in to_field])

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
            "subject": mail.subject,
            "from": sender,
            "sender": sender,
            "to": to_field,
            "recipient": to_field,
            "date": mail.date,
            "body": mail.body,
            "headers": mail.mail_header,
            "attachments": attachments
        }

    def _parse_msg_stream(self, raw_bytes):
        msg = extract_msg.Message(io.BytesIO(raw_bytes))
        
        sender = getattr(msg, 'sender', '')
        to_field = getattr(msg, 'to', '')
        
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
            "subject": msg.subject,
            "from": sender,
            "sender": sender,
            "to": to_field,
            "recipient": to_field,
            "date": msg.date,
            "body": msg.body,
            "headers": str(msg.header) if msg.header else "",
            "attachments": attachments
        }
        msg.close()
        return parsed_data
