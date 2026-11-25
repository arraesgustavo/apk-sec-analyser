"""Pydantic v2 schemas for structured LLM security triage reports."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Risk severity levels assigned to identified security findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingAnalysis(BaseModel):
    """Structured security triage details for a single Android manifest finding."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(
        description=(
            "Objective, concise title describing the security vulnerability "
            "(e.g., 'Exported Activity Without Permission Protection')."
        )
    )
    severity: Severity = Field(
        description=(
            "Overall risk severity level of the vulnerability: "
            "LOW, MEDIUM, HIGH, or CRITICAL."
        )
    )
    masvs_category: str = Field(
        description=(
            "Relevant OWASP MASVS category identifier "
            "(e.g., 'MASVS-PLATFORM', 'MASVS-NETWORK', 'MASVS-STORAGE', 'MASVS-CODE')."
        )
    )
    affected_component: str = Field(
        description=(
            "Specific Android component, permission, or application configuration "
            "affected by the issue (e.g., 'activity:.MainActivity', 'application', "
            "'android.permission.READ_SMS')."
        )
    )
    technical_impact: str = Field(
        description=(
            "Direct technical explanation of the security risk and exploitation "
            "consequences within the Android OS security model."
        )
    )
    poc_command: str = Field(
        description=(
            "Reproducible adb shell command (e.g., 'adb shell am start -n ...') "
            "or concrete verification steps in a controlled test environment to "
            "validate the exposure."
        )
    )
    remediation_code: str = Field(
        description=(
            "Corrected configuration or code snippet in AndroidManifest.xml XML "
            "or Java/Kotlin that remediates the vulnerability."
        )
    )


class SecurityReport(BaseModel):
    """Complete structured security report produced by the LLM triage step."""

    model_config = ConfigDict(extra="forbid")

    package_name: str = Field(
        description="Android application package name analyzed (e.g., 'com.example.app')."
    )
    executive_summary: str = Field(
        description=(
            "Concise high-level summary of the application's security posture "
            "and the most critical risks identified."
        )
    )
    findings: list[FindingAnalysis] = Field(
        description=(
            "Ordered list of triaged security findings. May be empty when no "
            "security issues are present."
        )
    )
