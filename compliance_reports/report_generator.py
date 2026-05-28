"""PDF report generator for HIPAA audit findings (ReportLab)."""
import datetime
import os

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


class ReportGenerator:
    def __init__(self, findings, output_file="HIPAA_Audit_Report.pdf"):
        self.findings = findings
        self.output_file = output_file
        self.styles = getSampleStyleSheet()

    @staticmethod
    def _status_color(status):
        return {
            "PASS": colors.green,
            "FAIL": colors.red,
            "WARN": colors.orange,
            "ERROR": colors.HexColor("#b8860b"),
        }.get(status, colors.black)

    def generate_report(self):
        doc = SimpleDocTemplate(self.output_file, pagesize=letter)
        story = []
        normal = self.styles["Normal"]
        small = self.styles["BodyText"]

        story.append(Paragraph("HIPAA Security Rule Compliance Audit Report", self.styles["Title"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph(
            f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal))
        story.append(Spacer(1, 24))

        total = len(self.findings)
        passed = sum(1 for f in self.findings if f["status"] == "PASS")
        failed = sum(1 for f in self.findings if f["status"] == "FAIL")
        warned = sum(1 for f in self.findings if f["status"] == "WARN")
        errors = sum(1 for f in self.findings if f["status"] == "ERROR")
        scored = passed + failed
        rate = f"{(passed / scored * 100):.0f}%" if scored else "N/A"

        story.append(Paragraph("Executive Summary", self.styles["Heading2"]))
        summary = (
            f"The audit completed {total} checks. Compliance rate (pass / pass+fail): "
            f"<b>{rate}</b>.<br/>"
            f"<font color='green'>Passed: {passed}</font> | "
            f"<font color='red'>Failed: {failed}</font> | "
            f"<font color='orange'>Warnings: {warned}</font> | "
            f"<font color='#b8860b'>Errors: {errors}</font>"
        )
        story.append(Paragraph(summary, normal))
        story.append(Spacer(1, 24))

        story.append(Paragraph("Detailed Findings", self.styles["Heading2"]))
        story.append(Spacer(1, 12))

        header = ["Status", "Component", "Finding", "HIPAA Reference"]
        table_data = [header]
        for f in self.findings:
            ref = f.get("citation", "")
            safeguard = f.get("safeguard", "")
            ref_text = f"<b>{ref}</b><br/>{safeguard}" if ref else ""
            table_data.append([
                f["status"],
                Paragraph(f["component"], small),
                Paragraph(f["finding"], small),
                Paragraph(ref_text, small),
            ])

        t = Table(table_data, colWidths=[50, 110, 215, 135], repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f7")]),
        ]
        for i, f in enumerate(self.findings):
            style.append(("TEXTCOLOR", (0, i + 1), (0, i + 1), self._status_color(f["status"])))
            style.append(("FONTNAME", (0, i + 1), (0, i + 1), "Helvetica-Bold"))
        t.setStyle(TableStyle(style))
        story.append(t)

        story.append(Spacer(1, 24))
        story.append(Paragraph(
            "<i>This report is an automated technical assessment and does not constitute "
            "legal advice or a certification of HIPAA compliance.</i>", small))

        doc.build(story)
        print(f"Report successfully generated at: {os.path.abspath(self.output_file)}")
        return self.output_file


if __name__ == "__main__":
    from hipaa_refs import make_finding
    demo = [
        make_finding("PASS", "DB", "All good", "encryption_at_rest"),
        make_finding("FAIL", "Network", "Bad TLS", "encryption_in_transit"),
    ]
    ReportGenerator(demo, "Test_Report.pdf").generate_report()
