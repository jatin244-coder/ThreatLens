"""Deterministic root-cause explanations for persisted scan findings."""

import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from app.schemas.scans import AnalysisResponse, FindingAnalysis
from app.services.scan_service import get_scan


_SENSITIVE_KEY = re.compile(
    r"(?:secret|token|password|passwd|authorization|cookie|credential|api[_-]?key|private[_-]?key|raw|body|content|(?:^|_)(?:ip|address|addresses)$)",
    re.IGNORECASE,
)

_HEADER_DETAILS: dict[str, tuple[str, str, str, str]] = {
    "header_content_security_policy": (
        "Missing Content-Security-Policy header",
        "Content-Security-Policy tells browsers which content sources are allowed to load. A missing header removes that browser-enforced policy; it does not by itself prove an exploitable injection.",
        "Configure the application or reverse proxy to emit a restrictive Content-Security-Policy appropriate for the site. Start with a reviewed report-only policy where compatibility is uncertain.",
        "Request the affected HTTPS endpoint and confirm the response contains one Content-Security-Policy header with the intended directives. Exercise important pages and browser features for regressions.",
    ),
    "header_strict_transport_security": (
        "Missing Strict-Transport-Security header",
        "Strict-Transport-Security instructs supporting browsers to use HTTPS for future requests. Its absence does not prove that HTTP traffic is exploitable or that HTTPS is unavailable.",
        "After HTTPS is correctly deployed for the host and its intended subdomains, emit Strict-Transport-Security with a reviewed max-age and, where appropriate, includeSubDomains and preload directives.",
        "Request the HTTPS endpoint and confirm the header value and directives. Verify HTTP-to-HTTPS behavior and ensure all covered subdomains are ready before broadening scope.",
    ),
    "header_x_content_type_options": (
        "Missing X-Content-Type-Options header",
        "The response does not advertise X-Content-Type-Options. This removes a browser signal that disables MIME sniffing; it does not establish that any served resource is misinterpreted.",
        "Emit X-Content-Type-Options: nosniff from the application or trusted edge for responses where the policy is applicable, and serve accurate Content-Type values.",
        "Request representative static and dynamic resources and confirm the exact header value is nosniff. Check that resource loading and downloads retain the intended content types.",
    ),
    "header_referrer_policy": (
        "Missing Referrer-Policy header",
        "The response does not advertise a Referrer-Policy. Referrer handling therefore follows browser defaults or other controls; this scan does not establish that sensitive data is present in URLs.",
        "Set an explicit Referrer-Policy, commonly a least-privilege policy such as strict-origin-when-cross-origin, after reviewing application navigation and analytics needs.",
        "Request the affected endpoint and confirm the policy header. Test same-origin and cross-origin navigation where referrer behavior matters.",
    ),
}


def _redact_value(value: Any, key: str | None = None) -> Any:
    """Redact secret-like evidence without exposing raw response content."""
    if key and _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(item_key): _redact_value(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item) for item in value]
    return value


def _safe_evidence(evidence: object, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(evidence, Mapping):
        return {}
    return {
        str(key): _redact_value(value, str(key))
        for key, value in evidence.items()
        if str(key) in allowed
    }


def _base_reference(index: int, finding: Mapping[str, object]) -> str:
    return f"finding-{index}:{finding.get('check_name', 'unknown')}"


def _unavailable(
    reference: str,
    finding: Mapping[str, object],
    reason: str,
    evidence: dict[str, Any],
) -> FindingAnalysis:
    return FindingAnalysis(
        finding_reference=reference,
        check_name=str(finding.get("check_name", "unknown")),
        status=str(finding.get("status", "UNKNOWN")),
        severity=str(finding.get("severity", "info")),
        analysis_available=False,
        title="Analysis unavailable",
        observed_evidence=evidence,
        establishes=reason,
        why_it_matters="No security conclusion is drawn because the finding does not contain enough evidence for a deterministic explanation.",
        likely_cause="Not established by the available finding.",
        cause_is_hypothesis=True,
        confidence="none",
        remediation=[],
        verification=[],
        limitations=["The persisted finding is incomplete, unsupported, or represents an indeterminate check outcome."],
        unavailable_reason=reason,
    )


def analyze_finding(index: int, finding: Mapping[str, object] | object) -> FindingAnalysis:
    """Analyze one persisted finding without inferring unobserved system state."""
    if not isinstance(finding, Mapping):
        return _unavailable(
            f"finding-{index}:unknown",
            {},
            "The persisted finding is not an object.",
            {},
        )
    check_name = str(finding.get("check_name", "unknown"))
    status = str(finding.get("status", "UNKNOWN"))
    severity = str(finding.get("severity", "info"))
    reference = _base_reference(index, finding)
    evidence = finding.get("evidence")

    if check_name in _HEADER_DETAILS:
        title, why_it_matters, remediation, verification = _HEADER_DETAILS[check_name]
        observed = _safe_evidence(evidence, {"header", "present"})
        if not observed.get("header") or not isinstance(observed.get("present"), bool):
            return _unavailable(reference, finding, "Header presence evidence is incomplete.", observed)
        if status not in {"PASS", "FAIL"}:
            return _unavailable(reference, finding, f"The header check ended with {status}; presence was not a definitive security result.", observed)
        if status == "PASS" and observed["present"] is not True:
            return _unavailable(reference, finding, "The finding status and header presence evidence are inconsistent.", observed)
        if status == "FAIL" and observed["present"] is not False:
            return _unavailable(reference, finding, "The finding status and header presence evidence are inconsistent.", observed)
        return FindingAnalysis(
            finding_reference=reference,
            check_name=check_name,
            status=status,
            severity=severity,
            analysis_available=True,
            title=title if status == "FAIL" else f"{observed['header']} header observed",
            observed_evidence=observed,
            establishes=(
                f"The scan observed that {observed['header']} was absent from the checked response."
                if status == "FAIL"
                else f"The scan observed that {observed['header']} was present in the checked response."
            ),
            why_it_matters=(
                why_it_matters
                if status == "FAIL"
                else f"The scan observed {observed['header']} in the checked response. This limited observation does not assess the policy's completeness or every response."
            ),
            likely_cause=(
                "The application or an upstream proxy may not be configured to emit this header. This is a hypothesis; the scan cannot identify the responsible configuration layer."
                if status == "FAIL"
                else "No cause analysis is needed for this passing observation."
            ),
            cause_is_hypothesis=status == "FAIL",
            confidence="high",
            remediation=[remediation] if status == "FAIL" else ["Keep the observed policy under configuration and regression-test coverage."],
            verification=[verification],
            limitations=["Header presence alone does not prove the policy is complete, effective for every response, or sufficient for the application."],
        )

    if check_name == "tls_certificate":
        observed = _safe_evidence(evidence, {"expires_at", "remaining_days", "reason"})
        if status == "FAIL" and isinstance(observed.get("expires_at"), str) and isinstance(observed.get("remaining_days"), (int, float)) and observed["remaining_days"] < 0:
            return FindingAnalysis(
                finding_reference=reference,
                check_name=check_name,
                status=status,
                severity=severity,
                analysis_available=True,
                title="TLS certificate expired",
                observed_evidence=observed,
                establishes="The scan recorded an expiry timestamp and a negative remaining-days value, establishing that the observed certificate was expired at scan time.",
                why_it_matters="Clients may reject the TLS connection, causing outages or preventing users from establishing an authenticated HTTPS session.",
                likely_cause="Certificate renewal, deployment, or certificate-selection configuration may have failed. This is a hypothesis about the operational cause.",
                cause_is_hypothesis=True,
                confidence="high",
                remediation=["Renew the certificate with a trusted certificate authority, deploy the complete intended chain to the serving endpoint, and remove or replace expired certificate material."],
                verification=["Repeat the HTTPS scan and confirm a non-expired certificate is served with the intended hostname and chain from each relevant edge or load balancer."],
                limitations=["The finding describes the certificate observed from the scan vantage point and does not identify every serving edge or internal certificate configuration."],
            )
        if status == "PASS" and isinstance(observed.get("expires_at"), str) and isinstance(observed.get("remaining_days"), (int, float)) and observed["remaining_days"] >= 0:
            return FindingAnalysis(
                finding_reference=reference,
                check_name=check_name,
                status=status,
                severity=severity,
                analysis_available=True,
                title="TLS certificate expiry not reached",
                observed_evidence=observed,
                establishes="The scan recorded a certificate expiry timestamp with a non-negative remaining-days value.",
                why_it_matters="A currently unexpired certificate supports continued TLS availability, but it does not establish complete certificate-chain, hostname, or operational coverage beyond this scan.",
                likely_cause="No cause analysis is needed for this passing observation.",
                cause_is_hypothesis=False,
                confidence="high",
                remediation=["Continue monitoring certificate expiry and renew before the remaining validity window is exhausted."],
                verification=["Repeat the scan and confirm the intended certificate remains valid and matches the deployed hostname and chain."],
                limitations=["The analysis is limited to expiry evidence returned by the scanner at scan time."],
            )
        if status in {"ERROR", "UNKNOWN"}:
            return _unavailable(reference, finding, f"The TLS check ended with {status}; certificate expiry was not established.", observed)
        return _unavailable(reference, finding, "Certificate evidence is incomplete or does not establish an expiry condition.", observed)

    if check_name == "https_connectivity_and_status":
        observed = _safe_evidence(evidence, {"status_code", "reason"})
        if status == "ERROR":
            return _unavailable(reference, finding, "HTTPS connectivity could not be established; this is not a confirmed vulnerability.", observed)
        if status == "PASS" and isinstance(observed.get("status_code"), int):
            return FindingAnalysis(
                finding_reference=reference,
                check_name=check_name,
                status=status,
                severity=severity,
                analysis_available=True,
                title="HTTPS endpoint responded",
                observed_evidence=observed,
                establishes=f"The checked endpoint returned HTTP status {observed['status_code']}.",
                why_it_matters="The bounded HTTPS request reached an endpoint and received a successful or redirect response.",
                likely_cause="No cause analysis is needed for this passing observation.",
                cause_is_hypothesis=False,
                confidence="high",
                remediation=["Maintain the tested HTTPS availability and review status changes through normal monitoring."],
                verification=["Repeat the bounded HTTPS request and confirm the expected status remains in the successful or redirect range."],
                limitations=["A response status does not assess application authorization, content security, or all routes."],
            )
        if status == "FAIL" and isinstance(observed.get("status_code"), int):
            return FindingAnalysis(
                finding_reference=reference,
                check_name=check_name,
                status=status,
                severity=severity,
                analysis_available=True,
                title="Unexpected HTTPS response status",
                observed_evidence=observed,
                establishes=f"The checked endpoint returned HTTP status {observed['status_code']}.",
                why_it_matters="The endpoint did not return a successful or redirect response to this bounded request; this may indicate availability, routing, or application behavior rather than a security vulnerability.",
                likely_cause="The endpoint, route, access policy, or upstream service may be configured to return this status. The scan cannot determine which cause applies.",
                cause_is_hypothesis=True,
                confidence="high",
                remediation=["Confirm that the intended public endpoint should respond successfully to an authorized request, then review routing, access controls, and upstream service health if the status is unexpected."],
                verification=["Repeat the request with the intended authentication and application context and confirm the expected status code."],
                limitations=["A status code alone does not establish the root cause or prove a vulnerability."],
            )
        return _unavailable(reference, finding, "HTTPS status evidence is incomplete or not a confirmed failure.", observed)

    if check_name == "dns_resolution":
        observed = _safe_evidence(evidence, {"record_types", "address_count", "reason"})
        if status == "ERROR":
            return _unavailable(reference, finding, "DNS resolution failed or was unsafe to use; this does not establish a confirmed vulnerability.", observed)
        if status == "PASS" and isinstance(observed.get("address_count"), int):
            return FindingAnalysis(
                finding_reference=reference,
                check_name=check_name,
                status=status,
                severity=severity,
                analysis_available=True,
                title="DNS resolution completed",
                observed_evidence=observed,
                establishes="The scanner resolved the target to validated DNS answers for the recorded address count and record types.",
                why_it_matters="Resolution is required before the bounded network checks can run, but successful resolution is not a security guarantee.",
                likely_cause="No cause analysis is needed for this passing observation.",
                cause_is_hypothesis=False,
                confidence="high",
                remediation=["Maintain controlled DNS ownership and monitor intended records for unexpected changes."],
                verification=["Repeat the scan and compare the validated record types and answer count with the intended DNS configuration."],
                limitations=["The scanner checks only the bounded resolver results available at scan time and does not audit DNS administration or delegation."],
            )
        return _unavailable(reference, finding, "DNS evidence is incomplete or indeterminate.", observed)

    return _unavailable(
        reference,
        finding,
        f"No deterministic analyzer is registered for check '{check_name}'.",
        _redact_value(evidence) if isinstance(evidence, Mapping) else {},
    )


def analyze_findings(findings: list[Mapping[str, object]] | object) -> list[FindingAnalysis]:
    """Analyze a possibly malformed persisted collection without crashing."""
    if not isinstance(findings, list):
        return []
    return [analyze_finding(index, finding) for index, finding in enumerate(findings)]


def get_scan_analysis(scan_id: str, database_url: str) -> AnalysisResponse | None:
    scan = get_scan(scan_id, database_url)
    if scan is None:
        return None
    findings = [finding for finding in scan.findings if isinstance(finding, Mapping)]
    return AnalysisResponse(
        scan_id=scan.id,
        generated_at=datetime.now(timezone.utc),
        analyses=analyze_findings(findings),
    )
