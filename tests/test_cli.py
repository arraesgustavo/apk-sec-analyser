"""Integration tests for the apk-analyzer CLI pipeline."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from apk_analyzer.cli import app
from apk_analyzer.extractor import ExtractorError
from apk_analyzer.llm_client import LLMAnalysisError
from apk_analyzer.schemas import FindingAnalysis, SecurityReport, Severity

runner = CliRunner()
FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULNERABLE_MANIFEST = FIXTURES_DIR / "vulnerable_manifest.xml"


def test_cli_no_llm_mode_generates_static_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify --no-llm runs the static pipeline and writes a Markdown report without LLM."""
    dummy_apk = tmp_path / "sample.apk"
    dummy_apk.write_bytes(b"PK\x03\x04fake-apk")
    report_path = tmp_path / "static_report.md"

    mock_decompile = MagicMock(return_value=VULNERABLE_MANIFEST)
    mock_llm_cls = MagicMock()

    monkeypatch.setattr("apk_analyzer.cli.decompile_apk", mock_decompile)
    monkeypatch.setattr("apk_analyzer.cli.LLMAnalyzerClient", mock_llm_cls)

    result = runner.invoke(
        app,
        ["--apk", str(dummy_apk), "--output", str(report_path), "--no-llm"],
    )

    assert result.exit_code == 0, result.output
    mock_decompile.assert_called_once()
    mock_llm_cls.assert_not_called()

    assert report_path.is_file()
    content = report_path.read_text(encoding="utf-8")
    assert "com.example.vulnerable" in content
    assert "--no-llm" in content
    assert "debuggable_application" in content
    assert "Findings : 7" in result.output
    assert str(report_path) in result.output


def test_cli_adb_package_with_llm_triage_generates_enriched_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify --adb-package runs pull, decompile, parse, LLM triage, and report save."""
    pulled_apk = tmp_path / "pulled.apk"
    pulled_apk.write_bytes(b"PK\x03\x04fake-apk")
    report_path = tmp_path / "llm_report.md"

    fake_report = SecurityReport(
        package_name="com.example.vulnerable",
        executive_summary="Critical misconfigurations detected.",
        findings=[
            FindingAnalysis(
                title="Debuggable Application",
                severity=Severity.HIGH,
                masvs_category="MASVS-CODE",
                affected_component="application",
                technical_impact="Allows debugger attachment via adb.",
                poc_command="adb shell run-as com.example.vulnerable ls",
                remediation_code='<application android:debuggable="false">',
            )
        ],
    )

    mock_pull = MagicMock(return_value=pulled_apk)
    mock_decompile = MagicMock(return_value=VULNERABLE_MANIFEST)
    mock_llm_instance = MagicMock()
    mock_llm_instance.analyze_manifest_findings.return_value = fake_report
    mock_llm_cls = MagicMock(return_value=mock_llm_instance)

    monkeypatch.setattr("apk_analyzer.cli.pull_apk_from_device", mock_pull)
    monkeypatch.setattr("apk_analyzer.cli.decompile_apk", mock_decompile)
    monkeypatch.setattr("apk_analyzer.cli.LLMAnalyzerClient", mock_llm_cls)

    result = runner.invoke(
        app,
        [
            "--adb-package",
            "com.example.vulnerable",
            "--output",
            str(report_path),
            "--model",
            "gpt-4o-mini",
        ],
    )

    assert result.exit_code == 0, result.output
    mock_pull.assert_called_once()
    mock_decompile.assert_called_once()
    mock_llm_cls.assert_called_once_with(model="gpt-4o-mini")
    mock_llm_instance.analyze_manifest_findings.assert_called_once()

    assert report_path.is_file()
    content = report_path.read_text(encoding="utf-8")
    assert "Debuggable Application" in content
    assert "MASVS-CODE" in content
    assert "Findings : 1" in result.output


def test_cli_handles_extractor_error_gracefully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify ExtractorError returns a non-zero exit code and friendly error message."""
    dummy_apk = tmp_path / "sample.apk"
    dummy_apk.write_bytes(b"PK\x03\x04fake-apk")

    monkeypatch.setattr(
        "apk_analyzer.cli.decompile_apk",
        MagicMock(side_effect=ExtractorError("apktool not found")),
    )

    result = runner.invoke(
        app,
        ["--apk", str(dummy_apk), "--no-llm"],
    )

    assert result.exit_code == 1
    assert "apktool not found" in result.output


def test_cli_handles_llm_error_gracefully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify LLMAnalysisError returns a non-zero exit code and friendly error message."""
    dummy_apk = tmp_path / "sample.apk"
    dummy_apk.write_bytes(b"PK\x03\x04fake-apk")

    mock_llm_instance = MagicMock()
    mock_llm_instance.analyze_manifest_findings.side_effect = LLMAnalysisError(
        "LLM request timed out"
    )

    monkeypatch.setattr(
        "apk_analyzer.cli.decompile_apk",
        MagicMock(return_value=VULNERABLE_MANIFEST),
    )
    monkeypatch.setattr(
        "apk_analyzer.cli.LLMAnalyzerClient",
        MagicMock(return_value=mock_llm_instance),
    )

    result = runner.invoke(
        app,
        ["--apk", str(dummy_apk)],
    )

    assert result.exit_code == 1
    assert "LLM request timed out" in result.output
