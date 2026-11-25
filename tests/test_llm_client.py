"""Offline unit tests for the OpenAI-compatible LLM security triage client."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from openai import APIConnectionError, APITimeoutError

from apk_analyzer.llm_client import (
    LLM_API_KEY_ENV,
    LLM_BASE_URL_ENV,
    LLM_MODEL_ENV,
    SYSTEM_PROMPT,
    LLMAnalysisError,
    LLMAnalyzerClient,
)
from apk_analyzer.schemas import FindingAnalysis, SecurityReport, Severity


def _sample_findings() -> list[dict[str, str]]:
    """Return representative filtered findings produced by manifest_parser."""
    return [
        {
            "finding_type": "debuggable_application",
            "component": "application",
            "attribute": "android:debuggable",
            "snippet": '<application android:debuggable="true">',
        },
        {
            "finding_type": "exported_component_without_permission",
            "component": "activity:.DebugExportedActivity",
            "attribute": "android:exported",
            "snippet": '<activity android:name=".DebugExportedActivity" android:exported="true">',
        },
    ]


def _sample_report_payload() -> dict[str, object]:
    """Return a valid SecurityReport JSON-serializable payload."""
    return {
        "package_name": "com.example.vulnerable",
        "executive_summary": "Application exposes high-risk debug and component misconfigurations.",
        "findings": [
            {
                "title": "Debuggable Application Enabled",
                "severity": "HIGH",
                "masvs_category": "MASVS-CODE",
                "affected_component": "application",
                "technical_impact": "Allows attackers with adb access to attach a debugger and inspect runtime memory.",
                "poc_command": "adb shell run-as com.example.vulnerable ls",
                "remediation_code": '<application android:debuggable="false">',
            },
            {
                "title": "Exported Activity Without Permission Protection",
                "severity": "MEDIUM",
                "masvs_category": "MASVS-PLATFORM",
                "affected_component": "activity:.DebugExportedActivity",
                "technical_impact": "Any installed third-party app can launch this activity directly.",
                "poc_command": "adb shell am start -n com.example.vulnerable/.DebugExportedActivity",
                "remediation_code": '<activity android:name=".DebugExportedActivity" android:exported="false" />',
            },
        ],
    }


def _mock_completion(
    *,
    parsed: object | None = None,
    content: str | None = None,
    refusal: str | None = None,
) -> SimpleNamespace:
    """Build a minimal fake OpenAI chat completion response."""
    message = SimpleNamespace(parsed=parsed, content=content, refusal=refusal)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def test_analyze_manifest_findings_parses_valid_json_response() -> None:
    """Verify valid JSON returned by the mocked API is converted into SecurityReport."""
    payload = _sample_report_payload()
    mock_sdk = MagicMock()
    mock_sdk.chat.completions.parse.return_value = _mock_completion(
        parsed=None,
        content=json.dumps(payload),
    )

    client = LLMAnalyzerClient(client=mock_sdk, model="gpt-4o-mini")
    report = client.analyze_manifest_findings(
        package_name="com.example.vulnerable",
        findings=_sample_findings(),
    )

    assert isinstance(report, SecurityReport)
    assert report.package_name == "com.example.vulnerable"
    assert len(report.findings) == 2
    assert all(isinstance(item, FindingAnalysis) for item in report.findings)
    assert report.findings[0].severity is Severity.HIGH
    assert report.findings[0].masvs_category == "MASVS-CODE"
    assert report.findings[1].severity is Severity.MEDIUM
    assert report.findings[1].affected_component == "activity:.DebugExportedActivity"


def test_analyze_manifest_findings_returns_structured_parsed_object() -> None:
    """Verify SDK-parsed SecurityReport objects are returned directly."""
    expected_report = SecurityReport.model_validate(_sample_report_payload())
    mock_sdk = MagicMock()
    mock_sdk.chat.completions.parse.return_value = _mock_completion(
        parsed=expected_report,
    )

    client = LLMAnalyzerClient(client=mock_sdk, model="gpt-4o-mini")
    report = client.analyze_manifest_findings(
        package_name="com.example.vulnerable",
        findings=_sample_findings(),
    )

    assert report == expected_report


def test_analyze_manifest_findings_sends_filtered_findings_and_package_name() -> None:
    """Verify the prompt sent to the LLM includes package_name and filtered findings."""
    findings = _sample_findings()
    expected_report = SecurityReport.model_validate(_sample_report_payload())
    mock_sdk = MagicMock()
    mock_sdk.chat.completions.parse.return_value = _mock_completion(
        parsed=expected_report,
    )

    client = LLMAnalyzerClient(client=mock_sdk, model="llama3.1")
    client.analyze_manifest_findings(
        package_name="com.example.vulnerable",
        findings=findings,
    )

    mock_sdk.chat.completions.parse.assert_called_once()
    call_kwargs = mock_sdk.chat.completions.parse.call_args.kwargs

    assert call_kwargs["model"] == "llama3.1"
    assert call_kwargs["response_format"] is SecurityReport
    assert call_kwargs["temperature"] == 0

    messages = call_kwargs["messages"]
    assert len(messages) == 2
    assert messages[0] == {"role": "system", "content": SYSTEM_PROMPT}
    assert messages[1]["role"] == "user"

    user_content = messages[1]["content"]
    assert "com.example.vulnerable" in user_content
    assert "debuggable_application" in user_content
    assert "exported_component_without_permission" in user_content
    assert "activity:.DebugExportedActivity" in user_content
    assert "<?xml" not in user_content


@pytest.mark.parametrize(
    "invalid_content",
    [
        "not valid json at all {{{",
        json.dumps({"package_name": "com.example.vulnerable"}),
        json.dumps(
            {
                "package_name": "com.example.vulnerable",
                "executive_summary": "Summary",
                "findings": [
                    {
                        "title": "Bad severity",
                        "severity": "EXTREME",
                        "masvs_category": "MASVS-CODE",
                        "affected_component": "application",
                        "technical_impact": "Impact",
                        "poc_command": "adb shell ...",
                        "remediation_code": "<application />",
                    }
                ],
            }
        ),
    ],
)
def test_analyze_manifest_findings_raises_on_malformed_or_invalid_json(
    invalid_content: str,
) -> None:
    """Verify malformed JSON or schema-invalid responses raise LLMAnalysisError."""
    mock_sdk = MagicMock()
    mock_sdk.chat.completions.parse.return_value = _mock_completion(
        parsed=None,
        content=invalid_content,
    )

    client = LLMAnalyzerClient(client=mock_sdk, model="gpt-4o-mini")

    with pytest.raises(LLMAnalysisError, match="validation"):
        client.analyze_manifest_findings(
            package_name="com.example.vulnerable",
            findings=_sample_findings(),
        )


def test_analyze_manifest_findings_handles_timeout_error() -> None:
    """Verify APITimeoutError is converted into a clean LLMAnalysisError."""
    mock_sdk = MagicMock()
    mock_sdk.chat.completions.parse.side_effect = APITimeoutError(request=MagicMock())

    client = LLMAnalyzerClient(client=mock_sdk, model="gpt-4o-mini", timeout=15.0)

    with pytest.raises(LLMAnalysisError, match="timed out"):
        client.analyze_manifest_findings(
            package_name="com.example.vulnerable",
            findings=_sample_findings(),
        )


def test_analyze_manifest_findings_handles_connection_error() -> None:
    """Verify APIConnectionError is converted into a clean LLMAnalysisError."""
    mock_sdk = MagicMock()
    mock_sdk.chat.completions.parse.side_effect = APIConnectionError(
        request=MagicMock()
    )

    client = LLMAnalyzerClient(
        client=mock_sdk,
        base_url="http://localhost:11434/v1",
        model="llama3.1",
    )

    with pytest.raises(LLMAnalysisError, match="Network error"):
        client.analyze_manifest_findings(
            package_name="com.example.vulnerable",
            findings=_sample_findings(),
        )


def test_client_requires_api_key_when_not_in_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify missing LLM_API_KEY raises LLMAnalysisError without making network calls."""
    monkeypatch.delenv(LLM_API_KEY_ENV, raising=False)

    with pytest.raises(LLMAnalysisError, match=LLM_API_KEY_ENV):
        LLMAnalyzerClient()


def test_client_reads_configuration_from_env_vars(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify OpenAI client initialization uses env vars for key, base_url, and model."""
    monkeypatch.setenv(LLM_API_KEY_ENV, "test-local-key")
    monkeypatch.setenv(LLM_BASE_URL_ENV, "http://localhost:11434/v1")
    monkeypatch.setenv(LLM_MODEL_ENV, "qwen2.5:7b")

    mock_openai_cls = MagicMock()
    monkeypatch.setattr("apk_analyzer.llm_client.OpenAI", mock_openai_cls)

    client = LLMAnalyzerClient(timeout=30.0)

    assert client.base_url == "http://localhost:11434/v1"
    assert client.model == "qwen2.5:7b"
    mock_openai_cls.assert_called_once_with(
        api_key="test-local-key",
        base_url="http://localhost:11434/v1",
        timeout=30.0,
    )
