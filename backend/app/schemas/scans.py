"""Pydantic schemas for the scan API."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator


class ScanCreateRequest(BaseModel):
    """Input required to queue an authorized hostname assessment."""

    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(min_length=1, max_length=253)
    authorization_confirmed: StrictBool


class ScanResponse(BaseModel):
    """Public representation of a queued scan record."""

    id: str
    hostname: str
    status: Literal["queued", "running", "completed", "error"]
    authorization_confirmed: bool
    created_at: datetime
    findings: list[dict[str, Any]] = Field(default_factory=list)
    score: int | None = Field(default=None, ge=0, le=100)
    risk: Literal["low", "moderate", "high", "critical"] | None = None


class ScanHistoryItem(BaseModel):
    """Dashboard-safe summary of one persisted scan."""

    id: str
    hostname: str
    status: Literal["queued", "running", "completed", "error"]
    created_at: datetime
    score: int | None = Field(default=None, ge=0, le=100)
    risk: Literal["low", "moderate", "high", "critical"] | None = None


class ScanHistoryResponse(BaseModel):
    """A bounded page of scan summaries."""

    items: list[ScanHistoryItem] = Field(default_factory=list)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
    total: int = Field(ge=0)


class ErrorResponse(BaseModel):
    """Standard error body for documented HTTP exceptions."""

    detail: str


class FindingAnalysis(BaseModel):
    """Deterministic explanation and guidance for one persisted finding."""

    finding_reference: str
    check_name: str
    status: str
    severity: str
    analysis_available: bool
    title: str
    observed_evidence: dict[str, Any] = Field(default_factory=dict)
    establishes: str
    why_it_matters: str
    likely_cause: str
    cause_is_hypothesis: bool
    confidence: Literal["high", "medium", "low", "none"]
    remediation: list[str] = Field(default_factory=list)
    verification: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    unavailable_reason: str | None = None
    # The existing English fields remain the stable primary contract. These
    # explicit language fields let clients render a complete bilingual result
    # without calling an external translation service.
    explanation_en: str = ""
    explanation_hi: str = ""
    remediation_en: list[str] = Field(default_factory=list)
    remediation_hi: list[str] = Field(default_factory=list)
    verification_en: list[str] = Field(default_factory=list)
    verification_hi: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def populate_bilingual_guidance(self) -> "FindingAnalysis":
        """Populate reviewed Hindi templates while retaining old fields."""
        hindi_by_check = {
            "header_content_security_policy": (
                "Content-Security-Policy ब्राउज़र को बताता है कि कौन-सी सामग्री लोड की जा सकती है। इस जाँच में यह header नहीं मिला; इससे अपने-आप हमला सिद्ध नहीं होता।",
                "वेब सर्वर या reverse proxy में उपयुक्त Content-Security-Policy जोड़ें। बदलाव से पहले report-only नीति से compatibility जाँचें।",
                "HTTPS endpoint को फिर जाँचें और सुनिश्चित करें कि इच्छित Content-Security-Policy header मौजूद है। मुख्य पेज और browser features भी जाँचें।",
            ),
            "header_strict_transport_security": (
                "Strict-Transport-Security समर्थित ब्राउज़र को आगे HTTPS इस्तेमाल करने के लिए कहता है। इसका न होना अपने-आप HTTP vulnerability सिद्ध नहीं करता।",
                "HTTPS सही तरह चालू होने के बाद reviewed max-age के साथ Strict-Transport-Security भेजें। includeSubDomains या preload केवल तैयारी पूरी होने पर जोड़ें।",
                "HTTPS response में header और उसके directives जाँचें। HTTP से HTTPS redirect तथा संबंधित subdomains भी verify करें।",
            ),
            "header_x_content_type_options": (
                "इस response में X-Content-Type-Options नहीं मिला। इससे MIME sniffing रोकने का browser संकेत उपलब्ध नहीं रहता; गलत content type सिद्ध नहीं होता।",
                "जहाँ लागू हो वहाँ X-Content-Type-Options: nosniff भेजें और हर resource का सही Content-Type रखें।",
                "मुख्य static और dynamic resources मँगाकर exact nosniff value और resource loading जाँचें।",
            ),
            "header_referrer_policy": (
                "इस response में Referrer-Policy नहीं मिली। Referrer व्यवहार browser defaults या दूसरे controls पर निर्भर हो सकता है।",
                "आमतौर पर strict-origin-when-cross-origin जैसी कम-अधिकार वाली Referrer-Policy सेट करें और analytics जरूरतों की समीक्षा करें।",
                "header की मौजूदगी जाँचें और same-origin तथा cross-origin navigation में referrer व्यवहार test करें।",
            ),
            "tls_certificate": (
                "स्कैन में TLS certificate की expiry जानकारी मिली है। यह निष्कर्ष केवल इसी scan समय और vantage point तक सीमित है।",
                "समय पर certificate renew करें, पूरी chain deploy करें और expired certificate को serving endpoint से हटाएँ।",
                "फिर scan चलाकर expiry, hostname और certificate chain की पुष्टि करें।",
            ),
            "https_connectivity_and_status": (
                "जाँचे गए HTTPS endpoint ने यह HTTP status लौटाया। status code अकेले root cause या vulnerability सिद्ध नहीं करता।",
                "अपेक्षित public response की पुष्टि करें और आवश्यकता होने पर routing, access policy तथा upstream service health की समीक्षा करें।",
                "उचित authorization और application context के साथ request दोहराकर expected status की पुष्टि करें।",
            ),
            "dns_resolution": (
                "स्कैन ने target के लिए सीमित DNS resolution परिणाम दर्ज किया। सफल resolution security guarantee नहीं है।",
                "DNS ownership नियंत्रित रखें और intended records में अनपेक्षित बदलाव monitor करें।",
                "फिर scan चलाकर record types और answer count को intended DNS configuration से मिलाएँ।",
            ),
        }
        generic = (
            "इस finding का परिणाम उपलब्ध evidence के आधार पर सीमित है; पर्याप्त जानकारी के बिना security निष्कर्ष नहीं निकाला गया है।",
            "इस finding की तकनीकी जाँच करें और बदलाव केवल अधिकृत तथा परीक्षण किए गए environment में करें।",
            "सुधार के बाद वही जाँच दोहराएँ और अपेक्षित evidence दर्ज करें।",
        )
        hindi = hindi_by_check.get(self.check_name, generic)
        if not self.analysis_available:
            hindi = generic
        elif self.status == "PASS" and self.check_name.startswith("header_"):
            hindi = (
                f"स्कैन में {self.check_name.removeprefix('header_').replace('_', '-')} header मिला। यह सीमित observation policy की पूर्णता या हर response की जाँच नहीं करता।",
                "देखे गए header को configuration में बनाए रखें और regression tests में इसकी जाँच करें।",
                "Representative responses में header की मौजूदगी और उसका intended value फिर जाँचें।",
            )
        elif self.check_name == "tls_certificate" and self.status == "PASS":
            hindi = (
                "स्कैन के समय certificate अभी valid था और expiry date भविष्य में थी। यह निष्कर्ष scan समय और उपलब्ध expiry evidence तक सीमित है।",
                "Certificate की validity monitor करते रहें और expiry से पहले आवश्यकता के अनुसार renew करें।",
                "फिर HTTPS scan चलाकर certificate की validity और intended hostname की पुष्टि करें।",
            )
        elif self.check_name == "https_connectivity_and_status" and self.status == "PASS":
            hindi = (
                "जाँचे गए HTTPS endpoint ने सफल response या redirect लौटाया। यह सीमित connectivity observation है।",
                "जाँची गई HTTPS availability बनाए रखें और status में बदलावों को सामान्य monitoring से track करें।",
                "Bounded HTTPS request दोहराकर अपेक्षित successful या redirect status की पुष्टि करें।",
            )

        # Preserve caller-provided bilingual content. The English legacy
        # fields remain the source of deterministic defaults only when a
        # corresponding explicit field was omitted or empty.
        self.explanation_en = self.explanation_en or self.why_it_matters
        self.explanation_hi = self.explanation_hi or hindi[0]
        self.remediation_en = self.remediation_en or list(self.remediation)
        self.remediation_hi = self.remediation_hi or ([hindi[1]] if self.remediation else [])
        self.verification_en = self.verification_en or list(self.verification)
        self.verification_hi = self.verification_hi or ([hindi[2]] if self.verification else [])
        return self


class AnalysisResponse(BaseModel):
    """On-demand analysis generated from the scan's current findings."""

    scan_id: str
    generated_at: datetime
    analyses: list[FindingAnalysis] = Field(default_factory=list)
