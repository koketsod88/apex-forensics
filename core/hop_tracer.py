import re
ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

class ApexHopTracer:
    def __init__(self, headers):
        self.headers = headers

    def trace_hops(self):
        """Extracts and parses Received headers to map email routing path."""
        hops = []
        received_lines = []

        # Handle both list of tuples and raw string headers
        if isinstance(self.headers, list):
            for k, v in self.headers:
                if k.lower() == 'received':
                    received_lines.append(v)
        elif isinstance(self.headers, dict):
            for k, v in self.headers.items():
                if k.lower() == 'received':
                    if isinstance(v, list):
                        received_lines.extend(v)
                    else:
                        received_lines.append(v)
        elif isinstance(self.headers, str):
            # Fallback regex search for Received blocks
            received_lines = re.findall(r'Received:\s+(.*?)(?=\r?\n[A-Z\-]+:|\Z)', self.headers, re.DOTALL)

        # Reverse to show chronological path (Origin -> Final Destination)
        received_lines.reverse()

        for idx, line in enumerate(received_lines, start=1):
            ips = ip_regex.findall(line)
            source_ip = ips[0] if ips else "Unknown"
            
            hops.append({
                "hop": idx,
                "source_ip": source_ip,
                "details": line.strip().replace('\n', ' ')
            })

        return hops
