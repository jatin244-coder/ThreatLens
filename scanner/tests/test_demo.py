import json

from cyberhealth_scanner.demo import demo_scan, main
from cyberhealth_scanner.questionnaire import QuestionnaireAnswers
from cyberhealth_scanner.scoring import calculate_score


def test_demo_scan_includes_all_mocked_check_types():
    result = demo_scan()

    assert result.scan_status == "complete"
    assert result.errors == []
    assert {
        "https",
        "tls_certificate",
        "security_headers",
        "dns_spf",
        "dns_dmarc",
        "dns_caa",
        "dns_dnssec",
    }.issubset({finding.check for finding in result.findings})
    assert result.questionnaire is not None
    assert result.score == calculate_score(
        result.findings,
        QuestionnaireAnswers(**result.questionnaire),
    ).score


def test_demo_scan_score_is_deterministic():
    first = demo_scan()
    second = demo_scan()

    assert first.score == second.score
    assert first.score_reasons == second.score_reasons
    assert 0 <= first.score <= 100


def test_demo_command_prints_formatted_json(capsys):
    main()

    output = capsys.readouterr().out
    parsed = json.loads(output)

    assert output.startswith("{\n  \"domain\"")
    assert parsed["domain"] == "demo.example.com"
    assert parsed["scan_status"] == "complete"