"""Unit tests for the AndroidManifest.xml static security parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from apk_analyzer.manifest_parser import (
    ManifestAnalysis,
    ManifestParseError,
    parse_manifest,
    parse_manifest_xml,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULNERABLE_MANIFEST = FIXTURES_DIR / "vulnerable_manifest.xml"
SECURE_MANIFEST = FIXTURES_DIR / "secure_manifest.xml"


def test_parse_vulnerable_manifest_detects_all_expected_findings() -> None:
    """Verify metadata and all deterministic findings in vulnerable_manifest.xml."""
    analysis = parse_manifest(VULNERABLE_MANIFEST)

    assert isinstance(analysis, ManifestAnalysis)
    assert analysis.package_name == "com.example.vulnerable"
    assert analysis.min_sdk_version == 21
    assert analysis.target_sdk_version == 33

    findings_by_key = {
        (finding.finding_type, finding.component): finding
        for finding in analysis.findings
    }

    expected_keys = {
        ("debuggable_application", "application"),
        ("cleartext_traffic_allowed", "application"),
        ("backup_allowed", "application"),
        ("exported_component_without_permission", "activity:.DebugExportedActivity"),
        ("exported_component_without_permission", "receiver:.SmsBroadcastReceiver"),
        ("dangerous_permission", "android.permission.READ_SMS"),
        ("dangerous_permission", "android.permission.ACCESS_FINE_LOCATION"),
    }

    assert set(findings_by_key.keys()) == expected_keys
    assert len(analysis.findings) == len(expected_keys)

    receiver_finding = findings_by_key[
        ("exported_component_without_permission", "receiver:.SmsBroadcastReceiver")
    ]
    assert "android.provider.Telephony.SMS_RECEIVED" in receiver_finding.snippet

    payload = analysis.to_dict()
    assert payload["package_name"] == "com.example.vulnerable"
    assert payload["min_sdk_version"] == 21
    assert payload["target_sdk_version"] == 33
    assert len(payload["findings"]) == len(expected_keys)
    for item in payload["findings"]:
        assert {"finding_type", "component", "attribute", "snippet"}.issubset(item)


def test_parse_vulnerable_manifest_ignores_permission_protected_service() -> None:
    """Ensure an exported Service protected by android:permission is not flagged."""
    analysis = parse_manifest(VULNERABLE_MANIFEST)

    flagged_components = {finding.component for finding in analysis.findings}
    assert "service:.ProtectedSyncService" not in flagged_components
    assert "android.permission.INTERNET" not in flagged_components


def test_parse_secure_manifest_produces_no_findings() -> None:
    """Verify that a hardened manifest triggers zero false positives."""
    analysis = parse_manifest(SECURE_MANIFEST)

    assert analysis.package_name == "com.example.secure"
    assert analysis.min_sdk_version == 26
    assert analysis.target_sdk_version == 34
    assert analysis.findings == ()
    assert analysis.to_dict() == {
        "package_name": "com.example.secure",
        "min_sdk_version": 26,
        "target_sdk_version": 34,
        "findings": [],
    }


def test_parse_manifest_xml_detects_implicitly_exported_component() -> None:
    """Verify components with intent-filter and without exported=false are flagged."""
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.implicit">
        <application>
            <receiver android:name=".ImplicitReceiver">
                <intent-filter>
                    <action android:name="com.example.ACTION_TRIGGER" />
                </intent-filter>
            </receiver>
        </application>
    </manifest>
    """
    analysis = parse_manifest_xml(xml_content)

    assert len(analysis.findings) == 1
    finding = analysis.findings[0]
    assert finding.finding_type == "implicitly_exported_component"
    assert finding.component == "receiver:.ImplicitReceiver"
    assert finding.attribute == "intent-filter"
    assert "com.example.ACTION_TRIGGER" in finding.snippet


def test_parse_manifest_missing_file_raises_error(tmp_path: Path) -> None:
    """Verify a nonexistent manifest path raises ManifestParseError."""
    missing_file = tmp_path / "does_not_exist.xml"

    with pytest.raises(ManifestParseError, match="not found"):
        parse_manifest(missing_file)


def test_parse_manifest_malformed_xml_raises_error(tmp_path: Path) -> None:
    """Verify malformed XML raises ManifestParseError for both file and string inputs."""
    malformed_xml = "<manifest><application android:debuggable='true'></manifest>"
    bad_file = tmp_path / "malformed.xml"
    bad_file.write_text(malformed_xml, encoding="utf-8")

    with pytest.raises(ManifestParseError):
        parse_manifest(bad_file)

    with pytest.raises(ManifestParseError):
        parse_manifest_xml(malformed_xml)


def test_parse_manifest_blocks_xxe_payload() -> None:
    """Verify defusedxml blocks DTD/XXE payloads with ManifestParseError."""
    xxe_payload = """<?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <manifest package="&xxe;" />
    """

    with pytest.raises(ManifestParseError):
        parse_manifest_xml(xxe_payload)
