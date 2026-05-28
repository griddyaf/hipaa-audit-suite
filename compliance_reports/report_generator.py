from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import datetime
import os

class ReportGenerator:
    def __init__(self, findings, output_file="HIPAA_Audit_Report.pdf"):
        self.findings = findings
        self.output_file = output_file
        self.styles = getSampleStyleSheet()

    def _get_status_color(self, status):
        if status == "PASS":
            return colors.green
        elif status == "FAIL":
            return colors.red
        else:
            return colors.orange

    def generate_report(self):
        """Generates a PDF report from the audit findings."""
        doc = SimpleDocTemplate(self.output_file, pagesize=letter)
        story = []

        # Title
        title_style = self.styles['Title']
        story.append(Paragraph("HIPAA Security Rule Compliance Audit Report", title_style))
        story.append(Spacer(1, 12))
        
        # Date
        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        story.append(Paragraph(f"Generated on: {date_str}", self.styles['Normal']))
        story.append(Spacer(1, 24))

        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['Heading2']))
        total_findings = len(self.findings)
        passed = sum(1 for f in self.findings if f['status'] == 'PASS')
        failed = sum(1 for f in self.findings if f['status'] == 'FAIL')
        errors = sum(1 for f in self.findings if f['status'] == 'ERROR')

        summary_text = f"The audit completed with {total_findings} total checks. <br/>"
        summary_text += f"<font color='green'>Passed: {passed}</font> | "
        summary_text += f"<font color='red'>Failed: {failed}</font> | "
        summary_text += f"<font color='orange'>Errors: {errors}</font>"
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 24))

        # Detailed Findings
        story.append(Paragraph("Detailed Findings", self.styles['Heading2']))
        story.append(Spacer(1, 12))

        # Create Table Data
        table_data = [["Status", "Component", "Finding Details"]]
        for f in self.findings:
            table_data.append([
                f['status'],
                Paragraph(f['component'], self.styles['Normal']),
                Paragraph(f['finding'], self.styles['Normal'])
            ])

        # Style the table
        t = Table(table_data, colWidths=[60, 150, 300])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))

        # Apply specific colors to the status column
        for i, row in enumerate(self.findings):
            color = self._get_status_color(row['status'])
            t.setStyle(TableStyle([
                ('TEXTCOLOR', (0, i+1), (0, i+1), color),
                ('FONTNAME', (0, i+1), (0, i+1), 'Helvetica-Bold')
            ]))

        story.append(t)
        
        # Build the PDF
        doc.build(story)
        print(f"Report successfully generated at: {os.path.abspath(self.output_file)}")

if __name__ == "__main__":
    sample_findings = [
        {"status": "PASS", "component": "DB", "finding": "All good"},
        {"status": "FAIL", "component": "Network", "finding": "Bad TLS"}
    ]
    ReportGenerator(sample_findings, "Test_Report.pdf").generate_report()
