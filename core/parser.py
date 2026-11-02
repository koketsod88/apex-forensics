import os
import mailparser
import extract_msg

class ApexParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.ext = os.path.splitext(filepath)[1].lower()

    def parse(self):
        """Unified parser handling both .eml and .msg files."""
        if self.ext == '.msg':
            return self._parse_msg()
        else:
            return self._parse_eml()

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
