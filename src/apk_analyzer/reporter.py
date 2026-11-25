"""Markdown security report renderer and writer for apk-sec-analyzer."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any

from apk_analyzer.schemas import FindingAnalysis, SecurityReport, Severity

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

_FENCE_OPEN_RE = re.compile(r"^```[a-zA-Z0-9_+-]*\s*\n")
_FENCE_CLOSE_RE = re.compile(r"\n```\s*$")


def _format_timestamp(generated_at: datetime | None) -> str:
    """Format an analysis timestamp in UTC."""
    ts = generated_at if generated_at is not None else datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    else:
        ts = ts.astimezone(timezone.utc)
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC")


def _escape_table_cell(value: str) -> str:
    """Escape pipe characters and collapse newlines for safe Markdown table cells."""
    cleaned = " ".join(str(value).splitlines()).strip()
    return cleaned.replace("|", r"\|")


def _sanitize_code_block(code: str) -> str:
    """Strip outer Markdown fences and neutralize internal triple backticks."""
    cleaned = code.strip()
    if cleaned.startswith("```") and cleaned.endswith("```"):
        cleaned = _FENCE_OPEN_RE.sub("", cleaned, count=1)
        cleaned = _FENCE_CLOSE_RE.sub("", cleaned, count=1)
        cleaned = cleaned.strip()

    while "```" in cleaned:
        cleaned = cleaned.replace("```", r"\`\`\`")

    return cleaned


def _format_fenced_code(code: str, language: str) -> str:
    """Render a sanitized fenced code block."""
    sanitized = _sanitize_code_block(code)
    return f"```{language}\n{sanitized}\n```"


def _detect_remediation_language(code: str) -> str:
    """Infer syntax highlighting language (xml, kotlin, or java) for remediation code."""
    sanitized = _sanitize_code_block(code)
    lowered = sanitized.lower()
    if sanitized.startswith("<") or any(
        tag in lowered
        for tag in (
            "<manifest",
            "<application",
            "<activity",
            "<service",
            "<receiver",
            "<provider",
            "<uses-permission",
            "android:",
        )
    ):
        return "xml"
    if any(token in sanitized for token in ("fun ", "val ", "override fun ")):
        return "kotlin"
    return "java"


def _render_finding_detail(index: int, finding: FindingAnalysis) -> list[str]:
    """Render a detailed Markdown subsection for a single LLM-triaged finding."""
    remediation_lang = _detect_remediation_language(finding.remediation_code)
    lines = [
        f"### {index}. {finding.title}",
        "",
        f"- **Severity:** `{finding.severity.value}`",
        f"- **OWASP MASVS:** `{finding.masvs_category}`",
        f"- **Affected Component:** `{finding.affected_component}`",
        "",
        "#### Technical Impact",
        "",
        finding.technical_impact.strip(),
        "",
        "#### Proof of Concept (adb shell / Verification)",
        "",
        _format_fenced_code(finding.poc_command, "bash"),
        "",
        "#### Remediation",
        "",
        _format_fenced_code(finding.remediation_code, remediation_lang),
        "",
    ]
    return lines


def render_markdown_report(
    report: SecurityReport,
    *,
    generated_at: datetime | None = None,
) -> str:
    """Render a structured SecurityReport into a complete Markdown document."""
    timestamp = _format_timestamp(generated_at)
    sorted_findings = sorted(
        report.findings,
        key=lambda item: _SEVERITY_ORDER.get(item.severity, 99),
    )

    lines: list[str] = [
        "# Android Security Analysis Report",
        "",
        f"- **Package:** `{report.package_name}`",
        f"- **Analysis Date:** {timestamp}",
        f"- **Total Findings:** {len(sorted_findings)}",
        "",
        "## Executive Summary",
        "",
        report.executive_summary.strip(),
        "",
        "## Findings Summary",
        "",
    ]

    if not sorted_findings:
        lines.extend(
            [
                "No security vulnerabilities were identified in this analysis.",
                "",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            "| Title | Severity | OWASP MASVS | Component |",
            "| --- | --- | --- | --- |",
        ]
    )

    for finding in sorted_findings:
        title = _escape_table_cell(finding.title)
        severity = _escape_table_cell(finding.severity.value)
        masvs = _escape_table_cell(finding.masvs_category)
        component = _escape_table_cell(finding.affected_component)
        lines.append(f"| {title} | {severity} | {masvs} | `{component}` |")

    lines.extend(["", "## Detailed Findings", ""])

    for index, finding in enumerate(sorted_findings, start=1):
        lines.extend(_render_finding_detail(index, finding))

    return "\n".join(lines)


def render_static_only_report(
    package_name: str,
    raw_findings: list[dict[str, Any]],
    *,
    generated_at: datetime | None = None,
) -> str:
    """Render a deterministic static-only Markdown report without LLM triage."""
    timestamp = _format_timestamp(generated_at)
    display_package = package_name.strip() if package_name and package_name.strip() else "<unknown>"

    lines: list[str] = [
        "# Android Static Security Analysis Report",
        "",
        f"- **Package:** `{display_package}`",
        f"- **Analysis Date:** {timestamp}",
        "- **Mode:** Static-only (`--no-llm`)",
        f"- **Total Findings:** {len(raw_findings)}",
        "",
        "## Executive Summary",
        "",
    ]

    if not raw_findings:
        lines.extend(
            [
                "Static analysis of `AndroidManifest.xml` completed with no deterministic security findings.",
                "",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            f"Static analysis of `AndroidManifest.xml` identified {len(raw_findings)} deterministic finding(s). "
            "LLM-assisted triage was skipped (`--no-llm`).",
            "",
            "## Findings Summary",
            "",
            "| Finding Type | Component | Attribute |",
            "| --- | --- | --- |",
        ]
    )

    for item in raw_findings:
        finding_type = _escape_table_cell(str(item.get("finding_type", "unknown")))
        component = _escape_table_cell(str(item.get("component", "unknown")))
        attribute = _escape_table_cell(str(item.get("attribute", "")))
        lines.append(f"| `{finding_type}` | `{component}` | `{attribute}` |")

    lines.extend(["", "## Detailed Static Findings", ""])

    for index, item in enumerate(raw_findings, start=1):
        finding_type = str(item.get("finding_type", "unknown"))
        component = str(item.get("component", "unknown"))
        attribute = str(item.get("attribute", ""))
        snippet = str(item.get("snippet", ""))
        details = str(item.get("details", "")).strip()

        lines.extend(
            [
                f"### {index}. {finding_type}",
                "",
                f"- **Component:** `{component}`",
                f"- **Attribute:** `{attribute}`",
                "",
            ]
        )
        if details:
            lines.extend([details, ""])
        if snippet:
            lines.extend([_format_fenced_code(snippet, "xml"), ""])

    return "\n".join(lines)


def save_report(content: str, output_path: Path | str) -> Path:
    """Write a rendered Markdown report to disk, creating parent directories if needed."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
