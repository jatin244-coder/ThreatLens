"""Read-only PDF report generation from persisted scan data."""

from __future__ import annotations

import json
import re
import unicodedata
from collections import defaultdict
from datetime import datetime, timezone
from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from app.schemas.scans import AnalysisResponse, FindingAnalysis, ScanResponse
from app.services.analysis_service import analyze_findings
from app.services.scan_service import get_scan


class ReportGenerationError(RuntimeError):
    """Raised when a report cannot be rendered from valid scan data."""


class ReportLabUnavailableError(RuntimeError):
    """Raised when the optional PDF renderer is not installed."""


def _load_reportlab() -> None:
    """Load ReportLab only when a PDF is requested."""
    global BaseDocTemplate, Frame, HRFlowable, KeepTogether, PageTemplate, Paragraph
    global Spacer, Table, TableStyle, ParagraphStyle, getSampleStyleSheet
    global colors, TA_CENTER, letter, inch
    try:
        from reportlab.lib import colors as reportlab_colors
        from reportlab.lib.enums import TA_CENTER as reportlab_ta_center
        from reportlab.lib.pagesizes import letter as reportlab_letter
        from reportlab.lib.styles import ParagraphStyle as reportlab_paragraph_style
        from reportlab.lib.styles import getSampleStyleSheet as reportlab_get_styles
        from reportlab.lib.units import inch as reportlab_inch
        from reportlab.platypus import (
            BaseDocTemplate as reportlab_base_doc_template,
            Frame as reportlab_frame,
            HRFlowable as reportlab_hr_flowable,
            KeepTogether as reportlab_keep_together,
            PageTemplate as reportlab_page_template,
            Paragraph as reportlab_paragraph,
            Spacer as reportlab_spacer,
            Table as reportlab_table,
            TableStyle as reportlab_table_style,
        )
    except ModuleNotFoundError as error:
        raise ReportLabUnavailableError("PDF report generation requires ReportLab") from error
    colors = reportlab_colors
    TA_CENTER = reportlab_ta_center
    letter = reportlab_letter
    inch = reportlab_inch
    ParagraphStyle = reportlab_paragraph_style
    getSampleStyleSheet = reportlab_get_styles
    BaseDocTemplate = reportlab_base_doc_template
    Frame = reportlab_frame
    HRFlowable = reportlab_hr_flowable
    KeepTogether = reportlab_keep_together
    PageTemplate = reportlab_page_template
    Paragraph = reportlab_paragraph
    Spacer = reportlab_spacer
    Table = reportlab_table
    TableStyle = reportlab_table_style


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9_.-]+")


def _text(value: Any) -> str:
    """Convert untrusted values to escaped, font-safe paragraph text.

    The report intentionally uses built-in English ReportLab fonts. Normalize
    accented Latin characters where possible and replace unsupported Unicode
    glyphs rather than allowing a PDF build to fail or emit corrupt text.
    """
    try:
        value_text = str(value)
    except Exception:
        value_text = "[unrenderable value]"
    value_text = unicodedata.normalize("NFKD", value_text).encode("ascii", "replace").decode("ascii")
    return escape(value_text, {"'": "&apos;", '"': "&quot;"}).replace("\n", "<br/>")


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_text(value), style)


def _safe_json(value: object) -> str:
    try:
        rendered = json.dumps(value, sort_keys=True, ensure_ascii=True)
    except (TypeError, ValueError):
        rendered = str(value)
    return rendered


def _safe_filename(scan_id: str) -> str:
    cleaned = _SAFE_FILENAME.sub("-", scan_id).strip(".-") or "scan"
    return f"threatlens-report-{cleaned}.pdf"


def _status_label(scan: ScanResponse) -> str:
    if scan.status == "completed":
        return "Completed"
    return f"{scan.status.title()} - incomplete assessment"


def _analysis_map(analysis: AnalysisResponse | None) -> dict[str, FindingAnalysis]:
    if analysis is None:
        return {}
    return {item.finding_reference: item for item in analysis.analyses}


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle", parent=base["Title"], fontName="Helvetica-Bold", fontSize=22,
            leading=27, textColor=colors.HexColor("#102A43"), alignment=TA_CENTER,
            spaceAfter=8,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle", parent=base["Normal"], fontName="Helvetica", fontSize=9,
            leading=12, textColor=colors.HexColor("#52606D"), alignment=TA_CENTER,
            spaceAfter=18,
        ),
        "h1": ParagraphStyle(
            "Section", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=14,
            leading=18, textColor=colors.HexColor("#102A43"), spaceBefore=12, spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "Finding", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=11,
            leading=14, textColor=colors.HexColor("#243B53"), spaceBefore=8, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"], fontName="Helvetica", fontSize=9,
            leading=13, textColor=colors.HexColor("#243B53"), spaceAfter=5,
        ),
        "small": ParagraphStyle(
            "Small", parent=base["BodyText"], fontName="Helvetica", fontSize=8,
            leading=10, textColor=colors.HexColor("#52606D"), spaceAfter=3,
        ),
        "label": ParagraphStyle(
            "Label", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=8,
            leading=10, textColor=colors.HexColor("#52606D"), spaceAfter=2,
        ),
        "note": ParagraphStyle(
            "Note", parent=base["BodyText"], fontName="Helvetica-Oblique", fontSize=8,
            leading=11, textColor=colors.HexColor("#7B341E"), backColor=colors.HexColor("#FFF7ED"),
            borderColor=colors.HexColor("#F6AD55"), borderWidth=0.5, borderPadding=6,
            spaceAfter=8,
        ),
    }


def _footer(canvas: Any, document: Any) -> None:
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#CBD5E0"))
    canvas.setLineWidth(0.5)
    canvas.line(document.leftMargin, 0.48 * inch, letter[0] - document.rightMargin, 0.48 * inch)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#718096"))
    canvas.drawString(document.leftMargin, 0.3 * inch, "ThreatLens - evidence-based security assessment")
    canvas.drawRightString(letter[0] - document.rightMargin, 0.3 * inch, f"Page {document.page}")
    canvas.restoreState()


def _summary_table(scan: ScanResponse, styles: dict[str, ParagraphStyle]) -> Table:
    score_value = "Not authoritative - scan is incomplete" if scan.status != "completed" else (
        f"{scan.score}/100" if scan.score is not None else "Unavailable"
    )
    risk_value = "Not authoritative - scan is incomplete" if scan.status != "completed" else (scan.risk or "Unavailable")
    data = [
        [_paragraph("Scan ID", styles["label"]), _paragraph(scan.id, styles["body"]), _paragraph("Status", styles["label"]), _paragraph(_status_label(scan), styles["body"])],
        [_paragraph("Assessed domain", styles["label"]), _paragraph(scan.hostname, styles["body"]), _paragraph("Generated", styles["label"]), _paragraph(datetime.now(timezone.utc).isoformat(), styles["body"])],
        [_paragraph("Score", styles["label"]), _paragraph(score_value, styles["body"]), _paragraph("Risk", styles["label"]), _paragraph(risk_value, styles["body"])],
    ]
    table = Table(data, colWidths=[0.82 * inch, 2.15 * inch, 0.82 * inch, 2.85 * inch], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _finding_block(
    index: int,
    finding: dict[str, object],
    analysis: FindingAnalysis | None,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    check_name = str(finding.get("check_name", "unknown"))
    status = str(finding.get("status", "UNKNOWN"))
    severity = str(finding.get("severity", "info"))
    reference = f"finding-{index}:{check_name}"
    title = analysis.title if analysis else "Analysis unavailable"
    observed = analysis.observed_evidence if analysis else {}
    story: list[Any] = [
        _paragraph(f"{title} - {check_name}", styles["h2"]),
        _paragraph(f"Reference: {reference} | Severity: {severity} | Status: {status}", styles["small"]),
        _paragraph("Observed evidence", styles["label"]),
        _paragraph(_safe_json(observed), styles["body"]),
    ]
    if analysis:
        sections = [
            ("What the evidence establishes", analysis.establishes),
            ("Why it matters", analysis.why_it_matters),
            ("Likely cause", f"{analysis.likely_cause} {'(hypothesis)' if analysis.cause_is_hypothesis else ''}"),
            ("Confidence", analysis.confidence),
        ]
        for label, value in sections:
            story.extend([_paragraph(label, styles["label"]), _paragraph(value, styles["body"])])
        for label, values in (("Remediation", analysis.remediation), ("Verification", analysis.verification), ("Limitations", analysis.limitations)):
            story.append(_paragraph(label, styles["label"]))
            if values:
                story.extend(_paragraph(f"- {value}", styles["body"]) for value in values)
            else:
                story.append(_paragraph("None provided.", styles["small"]))
    else:
        story.extend([
            _paragraph("No Phase 5 analysis was available for this finding.", styles["note"]),
            _paragraph("The report does not infer remediation or a security conclusion from unavailable analysis.", styles["body"]),
        ])
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E2E8F0"), spaceBefore=5, spaceAfter=4))
    return [KeepTogether(story)]


def _build_story(scan: ScanResponse, analysis: AnalysisResponse | None, styles: dict[str, ParagraphStyle]) -> list[Any]:
    generated = datetime.now(timezone.utc).isoformat()
    story: list[Any] = [
        _paragraph("ThreatLens Security Report", styles["title"]),
        _paragraph("Evidence-based assessment report", styles["subtitle"]),
        _summary_table(scan, styles),
        Spacer(1, 0.16 * inch),
        _paragraph("Assessment scope", styles["h1"]),
        _paragraph("This report summarizes bounded external checks performed for the explicitly authorized normalized hostname. It does not inspect application internals or represent a complete security audit.", styles["body"]),
    ]
    if scan.status != "completed":
        story.append(_paragraph(f"This scan is {scan.status}; findings and any stored score are not a completed assessment and are not presented as authoritative.", styles["note"]))

    findings = scan.findings
    confirmed_failures = [item for item in findings if item.get("status") == "FAIL"]
    if scan.status == "completed":
        summary = f"The completed scan contains {len(findings)} findings, including {len(confirmed_failures)} confirmed check failures. The score and risk shown above reflect only the persisted scoring rules."
    else:
        summary = f"The scan has {len(findings)} persisted findings, but completion was not established. No completed security conclusion is drawn."
    story.extend([_paragraph("Executive summary", styles["h1"]), _paragraph(summary, styles["body"])])

    story.append(_paragraph("Findings by severity and status", styles["h1"]))
    analysis_lookup = _analysis_map(analysis)
    grouped: dict[tuple[str, str], list[tuple[int, dict[str, object]]]] = defaultdict(list)
    for index, finding in enumerate(findings):
        grouped[(str(finding.get("severity", "info")), str(finding.get("status", "UNKNOWN")))].append((index, finding))
    if not grouped:
        story.append(_paragraph("No findings were persisted for this scan.", styles["body"]))
    else:
        for severity in _SEVERITY_ORDER:
            statuses = sorted(status for level, status in grouped if level == severity)
            for status in statuses:
                story.append(_paragraph(f"{severity.title()} - {status}", styles["h2"]))
                for index, finding in grouped[(severity, status)]:
                    reference = f"finding-{index}:{finding.get('check_name', 'unknown')}"
                    story.extend(_finding_block(index, finding, analysis_lookup.get(reference), styles))

    story.extend([
        _paragraph("Methodology and limitations", styles["h1"]),
        _paragraph("ThreatLens uses bounded DNS, HTTPS/TLS, response-status, and selected security-header checks. DNS answers and destinations are validated by the scanner safety policy, network reads are bounded, redirects are manually revalidated, and findings are based only on observations persisted with this scan.", styles["body"]),
        _paragraph("A PASS is limited to the tested check and vantage point. An ERROR or UNKNOWN result is not a confirmed vulnerability and does not prove that a control is absent or present. Remediation guidance is deterministic and should be verified in the target's authorized environment.", styles["body"]),
        _paragraph(f"Report generated at {generated}.", styles["small"]),
    ])
    return story


def generate_scan_report(scan_id: str, database_url: str) -> bytes | None:
    """Render a report from the current persisted scan without running it."""
    try:
        scan = get_scan(scan_id, database_url)
        if scan is None:
            return None
        _load_reportlab()
        finding_mappings = [finding for finding in scan.findings if isinstance(finding, dict)]
        analysis = AnalysisResponse(
            scan_id=scan.id,
            generated_at=datetime.now(timezone.utc),
            analyses=analyze_findings(finding_mappings),
        )
        output = BytesIO()
        styles = _styles()
        document = BaseDocTemplate(
            output,
            pagesize=letter,
            leftMargin=0.7 * inch,
            rightMargin=0.7 * inch,
            topMargin=0.65 * inch,
            bottomMargin=0.7 * inch,
            title="ThreatLens Security Report",
            author="ThreatLens",
        )
        frame = Frame(document.leftMargin, document.bottomMargin, document.width, document.height, id="normal")
        document.addPageTemplates([PageTemplate(id="report", frames=[frame], onPage=_footer)])
        document.build(_build_story(scan, analysis, styles))
        return output.getvalue()
    except ReportLabUnavailableError:
        raise
    except Exception as error:
        raise ReportGenerationError("security report could not be generated") from error


def report_filename(scan_id: str) -> str:
    return _safe_filename(scan_id)
