"""OpenAI-compatible LLM client for structured Android security triage."""

from __future__ import annotations

import json
import os
from typing import Any

from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AuthenticationError,
    OpenAI,
    OpenAIError,
    RateLimitError,
)
from pydantic import ValidationError

from apk_analyzer.schemas import SecurityReport

LLM_API_KEY_ENV = "LLM_API_KEY"
LLM_BASE_URL_ENV = "LLM_BASE_URL"
LLM_MODEL_ENV = "LLM_MODEL"

DEFAULT_LLM_MODEL = "gpt-4o-mini"
DEFAULT_LLM_TIMEOUT_SECONDS = 60.0

SYSTEM_PROMPT = (
    "You are a senior Android application security auditor following the OWASP MASVS "
    "standard. You receive deterministic static analysis findings extracted from an "
    "AndroidManifest.xml file in compact JSON format. For each finding, assess its "
    "severity, map it to the appropriate OWASP MASVS category, explain the concrete "
    "technical impact in the Android OS security model, provide a reproducible "
    "adb shell command or controlled verification steps, and supply corrected "
    "AndroidManifest.xml or Java/Kotlin remediation code. Base your report strictly "
    "on the provided findings without inventing unsupported vulnerabilities. If the "
    "findings list is empty, return an empty findings list and a concise executive "
    "summary stating that no manifest issues were detected."
)


class LLMAnalysisError(Exception):
    """Raised when LLM configuration, transport, or response validation fails."""


class LLMAnalyzerClient:
    """Client for triaging filtered AndroidManifest findings via OpenAI-compatible APIs."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        *,
        timeout: float = DEFAULT_LLM_TIMEOUT_SECONDS,
        client: OpenAI | None = None,
    ) -> None:
        raw_base_url = base_url if base_url is not None else os.getenv(LLM_BASE_URL_ENV)
        resolved_base_url = (
            raw_base_url.strip() if raw_base_url and raw_base_url.strip() else None
        )

        raw_model = model if model is not None else os.getenv(LLM_MODEL_ENV)
        resolved_model = (
            raw_model.strip()
            if raw_model is not None and raw_model.strip()
            else DEFAULT_LLM_MODEL
        )

        if client is None:
            raw_api_key = (
                api_key if api_key is not None else os.getenv(LLM_API_KEY_ENV)
            )
            resolved_api_key = (
                raw_api_key.strip() if raw_api_key and raw_api_key.strip() else None
            )
            if not resolved_api_key:
                raise LLMAnalysisError(
                    f"Missing LLM API key. Set the {LLM_API_KEY_ENV} environment "
                    "variable or pass api_key explicitly."
                )
            self._client = OpenAI(
                api_key=resolved_api_key,
                base_url=resolved_base_url,
                timeout=timeout,
            )
        else:
            self._client = client

        self.base_url = resolved_base_url
        self.model = resolved_model
        self.timeout = timeout

    def _build_user_prompt(
        self,
        package_name: str,
        findings: list[dict[str, Any]],
    ) -> str:
        """Serialize only the filtered manifest findings into a compact JSON prompt."""
        payload = {
            "package_name": package_name,
            "findings": findings,
        }
        return (
            "Analyze the following deterministic AndroidManifest.xml security findings "
            "and return a structured SecurityReport.\n\n"
            f"{json.dumps(payload, ensure_ascii=False, indent=2)}"
        )

    def analyze_manifest_findings(
        self,
        package_name: str,
        findings: list[dict[str, Any]],
    ) -> SecurityReport:
        """Send filtered manifest findings to the LLM and return a validated SecurityReport."""
        user_prompt = self._build_user_prompt(package_name, findings)

        try:
            response = self._client.chat.completions.parse(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                response_format=SecurityReport,
                temperature=0,
            )
        except APITimeoutError as exc:
            raise LLMAnalysisError(
                f"LLM request timed out after {self.timeout}s: {exc}"
            ) from exc
        except APIConnectionError as exc:
            endpoint = self.base_url or "default OpenAI API"
            raise LLMAnalysisError(
                f"Network error while connecting to LLM endpoint ({endpoint}): {exc}"
            ) from exc
        except AuthenticationError as exc:
            raise LLMAnalysisError(
                f"LLM authentication failed. Verify {LLM_API_KEY_ENV}: {exc}"
            ) from exc
        except RateLimitError as exc:
            raise LLMAnalysisError(f"LLM rate limit exceeded: {exc}") from exc
        except APIStatusError as exc:
            raise LLMAnalysisError(
                f"LLM API returned HTTP {exc.status_code}: {exc.message}"
            ) from exc
        except ValidationError as exc:
            raise LLMAnalysisError(
                f"LLM response failed SecurityReport schema validation: {exc}"
            ) from exc
        except OpenAIError as exc:
            raise LLMAnalysisError(
                f"Unexpected OpenAI SDK error during analysis: {exc}"
            ) from exc

        if not response.choices:
            raise LLMAnalysisError("LLM returned an empty choices list.")

        message = response.choices[0].message
        refusal = getattr(message, "refusal", None)
        if refusal:
            raise LLMAnalysisError(
                f"LLM refused to complete the security analysis: {refusal}"
            )

        parsed = getattr(message, "parsed", None)
        if parsed is not None:
            if isinstance(parsed, SecurityReport):
                return parsed
            try:
                return SecurityReport.model_validate(parsed)
            except ValidationError as exc:
                raise LLMAnalysisError(
                    f"LLM structured output failed SecurityReport validation: {exc}"
                ) from exc

        content = getattr(message, "content", None)
        if content:
            try:
                return SecurityReport.model_validate_json(content)
            except ValidationError as exc:
                raise LLMAnalysisError(
                    f"LLM JSON content failed SecurityReport validation: {exc}"
                ) from exc

        raise LLMAnalysisError(
            "LLM response contained neither a parsed SecurityReport nor JSON content."
        )
