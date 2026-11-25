"""Static security parser for AndroidManifest.xml files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as StdET

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

COMPONENT_TAGS: tuple[str, ...] = (
    "activity",
    "service",
    "receiver",
    "provider",
)

DANGEROUS_PERMISSIONS: frozenset[str] = frozenset(
    {
        "READ_SMS",
        "SEND_SMS",
        "RECEIVE_SMS",
        "RECEIVE_WAP_PUSH",
        "RECEIVE_MMS",
        "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
        "ACCESS_BACKGROUND_LOCATION",
        "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE",
        "RECORD_AUDIO",
        "CAMERA",
        "READ_CONTACTS",
        "WRITE_CONTACTS",
        "GET_ACCOUNTS",
        "READ_CALL_LOG",
        "WRITE_CALL_LOG",
        "CALL_PHONE",
        "READ_PHONE_STATE",
        "READ_PHONE_NUMBERS",
        "ANSWER_PHONE_CALLS",
        "ADD_VOICEMAIL",
        "USE_SIP",
        "PROCESS_OUTGOING_CALLS",
        "READ_CALENDAR",
        "WRITE_CALENDAR",
        "BODY_SENSORS",
        "ACTIVITY_RECOGNITION",
        "POST_NOTIFICATIONS",
        "READ_MEDIA_IMAGES",
        "READ_MEDIA_VIDEO",
        "READ_MEDIA_AUDIO",
        "BLUETOOTH_CONNECT",
        "BLUETOOTH_SCAN",
    }
)

_APPLICATION_BOOL_CHECKS: tuple[tuple[str, str, str], ...] = (
    (
        "debuggable",
        "debuggable_application",
        "Application is marked as debuggable, allowing debugger attachment.",
    ),
    (
        "usesCleartextTraffic",
        "cleartext_traffic_allowed",
        "Application permits unencrypted cleartext network traffic.",
    ),
    (
        "allowBackup",
        "backup_allowed",
        "Application allows backup of local app data via adb or cloud backup.",
    ),
)


class ManifestParseError(Exception):
    """Raised when AndroidManifest.xml cannot be safely read or parsed."""


@dataclass(frozen=True)
class ManifestFinding:
    """A single deterministic security finding extracted from AndroidManifest.xml."""

    finding_type: str
    component: str
    attribute: str
    snippet: str
    details: str = ""

    def to_dict(self) -> dict[str, str]:
        """Return a compact JSON-serializable representation for LLM context."""
        payload = {
            "finding_type": self.finding_type,
            "component": self.component,
            "attribute": self.attribute,
            "snippet": self.snippet,
        }
        if self.details:
            payload["details"] = self.details
        return payload


@dataclass(frozen=True)
class ManifestAnalysis:
    """Filtered metadata and deterministic findings from AndroidManifest.xml."""

    package_name: str | None
    min_sdk_version: int | None
    target_sdk_version: int | None
    findings: tuple[ManifestFinding, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a clean dictionary ready to be serialized for LLM triage."""
        return {
            "package_name": self.package_name,
            "min_sdk_version": self.min_sdk_version,
            "target_sdk_version": self.target_sdk_version,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _android_attr(element: StdET.Element, attr_name: str) -> str | None:
    """Read an attribute in the Android XML namespace."""
    return element.get(f"{ANDROID_NS}{attr_name}")


def _parse_optional_int(value: str | None) -> int | None:
    """Parse an integer attribute value, returning None if absent or non-numeric."""
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    try:
        return int(cleaned)
    except ValueError:
        return None


def _is_true(value: str | None) -> bool:
    """Return True if an XML boolean attribute equals 'true' (case-insensitive)."""
    return value is not None and value.strip().lower() == "true"


def _extract_sdk_versions(root: StdET.Element) -> tuple[int | None, int | None]:
    """Extract minSdkVersion and targetSdkVersion from uses-sdk elements."""
    min_sdk: int | None = None
    target_sdk: int | None = None

    for uses_sdk in root.findall("uses-sdk"):
        if min_sdk is None:
            min_sdk = _parse_optional_int(_android_attr(uses_sdk, "minSdkVersion"))
        if target_sdk is None:
            target_sdk = _parse_optional_int(
                _android_attr(uses_sdk, "targetSdkVersion")
            )

    return min_sdk, target_sdk


def _build_component_snippet(
    tag: str,
    name: str,
    exported: str | None,
    intent_actions: list[str],
) -> str:
    """Build a compact XML-like snippet describing an exported component."""
    attrs = [f'android:name="{name}"']
    if exported is not None:
        attrs.append(f'android:exported="{exported}"')
    opening = f"<{tag} {' '.join(attrs)}>"
    if intent_actions:
        actions_summary = ", ".join(intent_actions[:3])
        if len(intent_actions) > 3:
            actions_summary += ", ..."
        return f"{opening} (intent-filter actions: {actions_summary})"
    return opening


def _collect_intent_actions(component: StdET.Element) -> list[str]:
    """Collect action names declared inside a component's intent-filter elements."""
    actions: list[str] = []
    for intent_filter in component.findall("intent-filter"):
        for action in intent_filter.findall("action"):
            action_name = _android_attr(action, "name")
            if action_name and action_name not in actions:
                actions.append(action_name)
    return actions


def _analyze_application(application: StdET.Element) -> list[ManifestFinding]:
    """Inspect the application tag and its declared components for security issues."""
    findings: list[ManifestFinding] = []

    for attr_name, finding_type, details in _APPLICATION_BOOL_CHECKS:
        raw_value = _android_attr(application, attr_name)
        if _is_true(raw_value):
            findings.append(
                ManifestFinding(
                    finding_type=finding_type,
                    component="application",
                    attribute=f"android:{attr_name}",
                    snippet=f'<application android:{attr_name}="true">',
                    details=details,
                )
            )

    for tag in COMPONENT_TAGS:
        for component in application.findall(tag):
            comp_name = _android_attr(component, "name") or f"<unnamed {tag}>"
            exported_raw = _android_attr(component, "exported")
            exported_norm = (
                exported_raw.strip().lower() if exported_raw is not None else None
            )
            permission = _android_attr(component, "permission")
            has_permission = bool(permission and permission.strip())
            has_intent_filter = component.find("intent-filter") is not None

            if has_permission:
                continue

            if exported_norm == "true":
                intent_actions = (
                    _collect_intent_actions(component) if has_intent_filter else []
                )
                findings.append(
                    ManifestFinding(
                        finding_type="exported_component_without_permission",
                        component=f"{tag}:{comp_name}",
                        attribute="android:exported",
                        snippet=_build_component_snippet(
                            tag, comp_name, exported_raw, intent_actions
                        ),
                        details=(
                            f"Component '{comp_name}' ({tag}) is explicitly exported "
                            "without an android:permission restriction."
                        ),
                    )
                )
            elif has_intent_filter and exported_norm != "false":
                intent_actions = _collect_intent_actions(component)
                findings.append(
                    ManifestFinding(
                        finding_type="implicitly_exported_component",
                        component=f"{tag}:{comp_name}",
                        attribute="intent-filter",
                        snippet=_build_component_snippet(
                            tag, comp_name, exported_raw, intent_actions
                        ),
                        details=(
                            f"Component '{comp_name}' ({tag}) declares an intent-filter "
                            "without android:exported=\"false\" and without android:permission."
                        ),
                    )
                )

    return findings


def _analyze_permissions(root: StdET.Element) -> list[ManifestFinding]:
    """Identify dangerous Android permissions requested via uses-permission."""
    findings: list[ManifestFinding] = []
    seen_permissions: set[str] = set()

    for elem in root.findall("uses-permission"):
        perm_name = _android_attr(elem, "name")
        if not perm_name:
            continue
        cleaned_name = perm_name.strip()
        if cleaned_name in seen_permissions:
            continue

        if cleaned_name.startswith("android.permission."):
            short_name = cleaned_name.removeprefix("android.permission.")
        else:
            short_name = cleaned_name

        if short_name in DANGEROUS_PERMISSIONS:
            seen_permissions.add(cleaned_name)
            findings.append(
                ManifestFinding(
                    finding_type="dangerous_permission",
                    component=cleaned_name,
                    attribute="android:name",
                    snippet=f'<uses-permission android:name="{cleaned_name}" />',
                    details=f"Requests dangerous Android permission '{short_name}'.",
                )
            )

    return findings


def _analyze_root(root: StdET.Element) -> ManifestAnalysis:
    """Extract metadata and deterministic findings from a parsed manifest root element."""
    if root.tag != "manifest":
        raise ManifestParseError(
            f"Unexpected root XML element '{root.tag}'. Expected 'manifest'."
        )

    raw_package = root.get("package")
    package_name = raw_package.strip() if raw_package and raw_package.strip() else None
    min_sdk, target_sdk = _extract_sdk_versions(root)

    findings: list[ManifestFinding] = []
    application = root.find("application")
    if application is not None:
        findings.extend(_analyze_application(application))
    findings.extend(_analyze_permissions(root))

    return ManifestAnalysis(
        package_name=package_name,
        min_sdk_version=min_sdk,
        target_sdk_version=target_sdk,
        findings=tuple(findings),
    )


def parse_manifest_xml(xml_content: str | bytes) -> ManifestAnalysis:
    """Safely parse AndroidManifest.xml content from a string or bytes."""
    try:
        root = DefusedET.fromstring(xml_content)
    except (DefusedXmlException, StdET.ParseError) as exc:
        raise ManifestParseError(
            f"Failed to safely parse AndroidManifest.xml content: {exc}"
        ) from exc

    return _analyze_root(root)


def parse_manifest(manifest_path: Path | str) -> ManifestAnalysis:
    """Safely parse an AndroidManifest.xml file using defusedxml and return filtered findings."""
    path = Path(manifest_path)
    if not path.is_file():
        raise ManifestParseError(f"Manifest file not found: {path}")

    try:
        tree = DefusedET.parse(path)
    except (DefusedXmlException, StdET.ParseError, OSError) as exc:
        raise ManifestParseError(
            f"Failed to safely parse manifest file '{path}': {exc}"
        ) from exc

    return _analyze_root(tree.getroot())
