<div align="center">

```text
             _                                              _
  __ _ _ __ | | __     ___  ___  ___      __ _ _ __   __ _ | |_   _ ___  ___ _ __
 / _` | '_ \| |/ /____/ __|/ _ \/ __|____/ _` | '_ \ / _` || | | | / __|/ _ \ '__|
| (_| | |_) |   <_____\__ \  __/ (_|____| (_| | | | | (_| || | |_| \__ \  __/ |
 \__,_| .__/|_|\_\    |___/\___|\___|    \__,_|_| |_|\__,_||_|\__, |___/\___|_|
      |_|                                                     |___/
```

**Static Android APK manifest security analyzer with optional OWASP MASVS LLM triage**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Android OS](https://img.shields.io/badge/Android_OS-3DDC84?style=for-the-badge&logo=android&logoColor=black)](https://developer.android.com/)
[![Pydantic v2](https://img.shields.io/badge/Pydantic_v2-E92063?style=for-the-badge&logo=pydantic&logoColor=white)](https://docs.pydantic.dev/)
[![LLM Structured](https://img.shields.io/badge/LLM_Structured-412991?style=for-the-badge&logo=openai&logoColor=white)](https://platform.openai.com/docs/guides/structured-outputs)
[![Pytest](https://img.shields.io/badge/Pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![OWASP MASVS](https://img.shields.io/badge/OWASP_MASVS-000000?style=for-the-badge&logo=owasp&logoColor=white)](https://mas.owasp.org/MASVS/)

</div>

---

## Overview

`apk-sec-analyser` is a CLI tool for static security analysis of Android `AndroidManifest.xml` files from local `.apk` archives or packages pulled via `adb`. It decompiles the target APK with `apktool`, parses the manifest with `defusedxml`, and deterministically extracts high-signal misconfigurations (debuggable flags, cleartext traffic, backup settings, unprotected exported components, and dangerous permissions). When enabled, it sends only the filtered JSON findings to an OpenAI-compatible LLM using Pydantic v2 Structured Outputs to map each issue to OWASP MASVS, generate reproducible `adb shell` validation commands, and output XML remediation patches in Markdown.

## Architecture

```text
+--------------------+     +-----------+     +-------------------+     +-------------------+
| .apk / adb pull    | --> |  apktool  | --> | defusedxml Parser | --> | Filtered Findings |
+--------------------+     +-----------+     +-------------------+     +-------------------+
                                                                          |              |
                                                       default (LLM mode) |              | --no-llm
                                                                          v              |
                                                                +------------------+     |
                                                                |  LLM (Pydantic)  |     |
                                                                +------------------+     |
                                                                          |              |
                                                                          v              v
                                                                      +---------------------+
                                                                      |      report.md      |
                                                                      +---------------------+
```

All temporary APKs and decompiled directories are created inside `tempfile.TemporaryDirectory()` and removed automatically on exit, including error paths.

## Security & Design Decisions

- **Context pruning:** Only the deterministic, filtered findings JSON (`package_name` + matched issues) is sent to the LLM. Raw XML manifests are never transmitted, reducing token cost and preventing hallucinated findings.
- **Pipeline hardening:**
  - `defusedxml.ElementTree` blocks XML External Entity (XXE) and DTD expansion attacks during manifest parsing.
  - External commands (`adb`, `apktool`) are executed via `subprocess.run(..., shell=False)` with explicit argument lists and timeouts to prevent command injection.
  - `--adb-package` inputs are validated against a strict Android package regex (`^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$`) before reaching `adb`.
- **Deterministic contracts & offline tests:** LLM responses are constrained by Pydantic v2 schemas (`SecurityReport`, `FindingAnalysis`, `Severity`) with `extra="forbid"`. The `pytest` suite runs 100% offline with mocked SDK/subprocess boundaries and requires no `LLM_API_KEY`.

## Prerequisites & Installation

Required system dependencies:

- Python 3.11+
- `apktool` available in `PATH`
- `adb` (Android Platform Tools) available in `PATH` when using `--adb-package`

Install in editable mode with development dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Configuration

LLM settings are read exclusively from environment variables (no keys are hardcoded):

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `LLM_API_KEY` | Yes (unless `--no-llm`) | None | API key for the OpenAI-compatible provider (any non-empty string for local Ollama). |
| `LLM_BASE_URL` | No | OpenAI default | Custom OpenAI-compatible endpoint URL (e.g. OpenRouter, Ollama). |
| `LLM_MODEL` | No | `gpt-4o-mini` | Model identifier used for structured triage (overridable via `--model`). |

### OpenRouter

```bash
export LLM_BASE_URL="https://openrouter.ai/api/v1"
export LLM_API_KEY="sk-or-v1-your-key"
export LLM_MODEL="openai/gpt-4o-mini"
```

### Local Ollama

```bash
export LLM_BASE_URL="http://localhost:11434/v1"
export LLM_API_KEY="ollama"
export LLM_MODEL="llama3.1"
```

## Usage

Analyze a local APK with LLM triage:

```bash
apk-sec-analyser --apk ./samples/target.apk --output ./reports/target.md
```

Pull an installed package from a connected Android device via `adb` and analyze it:

```bash
apk-sec-analyser --adb-package com.example.target --output ./reports/target.md
```

Run static-only manifest analysis without calling any LLM:

```bash
apk-sec-analyser --apk ./samples/target.apk --no-llm --output ./reports/static.md
```

Run the offline test suite:

```bash
pytest -v
```

## Sample Report Output

````markdown
# Android Security Analysis Report

- **Package:** `com.example.vulnerable`
- **Analysis Date:** 2026-11-25 15:00:00 UTC
- **Total Findings:** 1

## Executive Summary

The application exposes an exported Activity without permission enforcement, allowing arbitrary third-party apps on the device to launch it directly.

## Findings Summary

| Title | Severity | OWASP MASVS | Component |
| --- | --- | --- | --- |
| Exported Activity Without Permission Protection | HIGH | MASVS-PLATFORM | `activity:.DebugExportedActivity` |

## Detailed Findings

### 1. Exported Activity Without Permission Protection

- **Severity:** `HIGH`
- **OWASP MASVS:** `MASVS-PLATFORM`
- **Affected Component:** `activity:.DebugExportedActivity`

#### Technical Impact

Because `android:exported="true"` is declared without an `android:permission` attribute, any installed application can invoke `.DebugExportedActivity` via explicit intents, bypassing internal navigation and authentication controls.

#### Proof of Concept (adb shell / Verification)

```bash
adb shell am start -n com.example.vulnerable/.DebugExportedActivity
```

#### Remediation

```xml
<activity
    android:name=".DebugExportedActivity"
    android:exported="false" />
```
````
