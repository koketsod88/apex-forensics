import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

class ApexPDFGenerator:
    def __init__(self, data, output_dir="reports_output"):
        self.data = data
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.subject = data.get('subject', 'No Subject')
        self.sender = data.get('sender') or data.get('from') or 'N/A'
        self.recipient = data.get('recipient') or data.get('to') or 'N/A'
        self.risk_score = data.get('risk_score', 10)
        self.severity = data.get('severity', 'LOW')
        self.urls = data.get('urls', [])
        self.attachments = data.get('attachments', [])
        self.authentication = data.get('authentication', {})

        if isinstance(self.sender, (list, tuple)):
            self.sender = ", ".join(str(s) for s in self.sender)
        if isinstance(self.recipient, (list, tuple)):
            self.recipient = ", ".join(str(r) for r in self.recipient)

        safe_subject = "".join([c if c.isalnum() else "_" for c in str(self.subject)])[:30]
        self.filename = os.path.join(self.output_dir, f"Apex_Forensic_Report_{safe_subject}.pdf")

    def build_pdf(self):
        doc = SimpleDocTemplate(
            self.filename,
            pagesize=letter,
            rightMargin=36, leftMargin=36,
            topMargin=36, bottomMargin=36
        )
        
        styles = getSampleStyleSheet()
        
        primary_color = colors.HexColor("#1A365D")
        accent_color = colors.HexColor("#3182CE")
        text_color = colors.HexColor("#2D3748")
        
        title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=22, leading=26, textColor=primary_color, fontName='Helvetica-Bold')
        subtitle_style = ParagraphStyle('DocSubTitle', parent=styles['Normal'], fontSize=11, leading=14, textColor=colors.HexColor("#718096"), fontName='Helvetica')
        heading_style = ParagraphStyle('SectionHeading', parent=styles['Heading2'], fontSize=13, leading=17, textColor=primary_color, fontName='Helvetica-Bold', spaceBefore=10, spaceAfter=4)
        body_style = ParagraphStyle('BodyDark', parent=styles['Normal'], fontSize=9, leading=13, textColor=text_color, fontName='Helvetica')

        elements = []

        # Header Title
        elements.append(Paragraph("APEX FORENSIC INVESTIGATION REPORT", title_style))
        elements.append(Paragraph("Automated Phishing Executive Examiner - Deep Forensic Engine v2.5", subtitle_style))
        elements.append(Spacer(1, 6))
        elements.append(HRFlowable(width="100%", thickness=2, color=accent_color, spaceBefore=4, spaceAfter=10))

        # Metadata Summary Table
        risk_color = colors.HexColor("#38A169") if self.risk_score < 40 else colors.HexColor("#DD6B20") if self.risk_score < 75 else colors.HexColor("#E53E3E")
        
        meta_data = [
            [Paragraph("<b>Subject:</b>", body_style), Paragraph(str(self.subject), body_style), Paragraph("<b>Risk Assessment:</b>", body_style)],
            [Paragraph("<b>Sender:</b>", body_style), Paragraph(str(self.sender), body_style), Paragraph(f"<b>{self.severity} ({self.risk_score}/100)</b>", ParagraphStyle('RiskText', parent=body_style, textColor=colors.white, fontName='Helvetica-Bold'))],
            [Paragraph("<b>Recipient:</b>", body_style), Paragraph(str(self.recipient), body_style), Paragraph("", body_style)]
        ]
        
        meta_table = Table(meta_data, colWidths=[70, 320, 150])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F7FAFC")),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#EDF2F7")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BACKGROUND', (2,1), (2,1), risk_color),
            ('ALIGN', (2,1), (2,1), 'CENTER'),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

        # Email Authentication Section (SPF / DKIM / DMARC)
        elements.append(Paragraph("Transport Authentication Analysis (SPF / DKIM / DMARC)", heading_style))
        spf = self.authentication.get('spf', 'NOT_FOUND')
        dkim = self.authentication.get('dkim', 'NOT_FOUND')
        dmarc = self.authentication.get('dmarc', 'NOT_FOUND')
        
        auth_text = f"<b>SPF:</b> {spf} | <b>DKIM:</b> {dkim} | <b>DMARC:</b> {dmarc}"
        elements.append(Paragraph(auth_text, body_style))
        elements.append(Spacer(1, 8))

        # Extracted Defanged URLs Section
        elements.append(Paragraph("Extracted & Defanged Indicators of Compromise (URLs)", heading_style))
        if self.urls:
            url_rows = [["Original URL", "Defanged IOC"]]
            for item in self.urls[:10]: # Limit to top 10 for neat PDF layout
                url_rows.append([Paragraph(item['original'], body_style), Paragraph(item['defanged'], body_style)])
            
            url_table = Table(url_rows, colWidths=[240, 300])
            url_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#EDF2F7")),
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E0")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            elements.append(url_table)
        else:
            elements.append(Paragraph("No URLs detected in the analyzed message body.", body_style))
        
        elements.append(Spacer(1, 10))

        # Attachments Section
        elements.append(Paragraph("Attachment Forensic Analysis", heading_style))
        if self.attachments:
            att_rows = [["Filename", "SHA-256 Hash", "Executable?"]]
            for att in self.attachments:
                fname = att.get('filename', 'unknown')
                fhash = att.get('sha256', 'N/A')
                fexec = str(att.get('is_executable', False))
                att_rows.append([Paragraph(fname, body_style), Paragraph(fhash[:24] + "...", body_style), Paragraph(fexec, body_style)])
            
            att_table = Table(att_rows, colWidths=[140, 300, 100])
            att_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#EDF2F7")),
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E0")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            elements.append(att_table)
        else:
            elements.append(Paragraph("No attachments detected in the analyzed sample.", body_style))
        
        elements.append(Spacer(1, 10))

        # Strategic Recommendations
        elements.append(Paragraph("Strategic Recommendations & Remediation Playbook", heading_style))
        recs = [
            "<b>1. Gateway Block:</b> Add extracted malicious URLs and file hashes to your Secure Email Gateway (SEG) blocklist.",
            "<b>2. Authentication Enforcement:</b> Ensure strict DMARC rejection policies are enforced for your organizational domains.",
            "<b>3. Tenant Purge:</b> Run automated message purge commands across Exchange Online to clear matching messages."
        ]
        for rec in recs:
            elements.append(Paragraph(rec, body_style))
            elements.append(Spacer(1, 3))

        doc.build(elements)
        return self.filename
