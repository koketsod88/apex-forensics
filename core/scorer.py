class ApexRiskScorer:
    def __init__(self, parsed_data):
        self.data = parsed_data

    def evaluate(self):
        """Evaluates risk score based on attachments, defanged URLs, and authentication failures."""
        score = 10
        
        # Check attachments for executables
        attachments = self.data.get('attachments', [])
        for att in attachments:
            if att.get('is_executable', False):
                score += 40
        
        # Check URLs
        urls = self.data.get('urls', [])
        if len(urls) > 0:
            score += len(urls) * 5

        # Check Authentication Failures (SPF / DKIM / DMARC)
        auth = self.data.get('authentication', {})
        if auth.get('spf') == 'FAIL':
            score += 20
        if auth.get('dkim') == 'FAIL':
            score += 20
        if auth.get('dmarc') == 'FAIL':
            score += 30

        # Cap score at 100
        score = min(score, 100)
        
        # Determine severity tier
        if score < 40:
            severity = "LOW"
        elif score < 75:
            severity = "MEDIUM"
        else:
            severity = "HIGH"

        return {
            "risk_score": score,
            "severity": severity
        }
