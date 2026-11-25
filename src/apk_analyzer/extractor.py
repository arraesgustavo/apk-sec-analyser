"""External tool wrappers for pulling and decompiling Android APKs."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

ANDROID_PACKAGE_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$"
)

DEFAULT_ADB_TIMEOUT_SECONDS = 60
DEFAULT_APKTOOL_TIMEOUT_SECONDS = 120


class ExtractorError(Exception):
    """Base exception for APK extraction and decompilation errors."""


class MissingToolError(ExtractorError):
    """Raised when a required external CLI executable is not found in PATH."""


class InvalidPackageNameError(ExtractorError):
    """Raised when an Android package name fails strict validation."""


class SubprocessExecutionError(ExtractorError):
    """Raised when an external command fails or exceeds its timeout."""


class DecompilationError(ExtractorError):
    """Raised when apktool output is missing expected decompiled artifacts."""


def ensure_tool_available(tool_name: str) -> str:
    """Verify that an external executable is available in PATH.

    Returns the resolved executable path or raises MissingToolError.
    """
    resolved = shutil.which(tool_name)
    if resolved is None:
        raise MissingToolError(
            f"Required tool '{tool_name}' was not found in PATH. "
            f"Please install '{tool_name}' and ensure it is accessible."
        )
    return resolved


def validate_package_name(package_name: str) -> str:
    """Validate an Android package name using a strict regex.

    Rejects malformed names, whitespace, and option-like prefixes to prevent
    argument injection when invoking adb.
    """
    if not isinstance(package_name, str) or not ANDROID_PACKAGE_PATTERN.fullmatch(
        package_name
    ):
        raise InvalidPackageNameError(
            f"Invalid Android package name: {package_name!r}. "
            "Expected dot-separated segments containing only letters, digits, and underscores "
            "(e.g. 'com.example.app')."
        )
    return package_name


def _run_command(
    command: list[str],
    *,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    """Run an external command safely without a shell and wrap subprocess errors."""
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        cmd_display = " ".join(command)
        raise SubprocessExecutionError(
            f"Command timed out after {timeout}s: {cmd_display}"
        ) from exc
    except subprocess.CalledProcessError as exc:
        cmd_display = " ".join(command)
        stderr_snippet = (exc.stderr or exc.stdout or "").strip()
        detail = f": {stderr_snippet}" if stderr_snippet else ""
        raise SubprocessExecutionError(
            f"Command failed with exit code {exc.returncode} ({cmd_display}){detail}"
        ) from exc


def _extract_base_apk_path(pm_output: str, package_name: str) -> str:
    """Parse 'adb shell pm path' output and return the remote base.apk path."""
    apk_paths: list[str] = []
    for raw_line in pm_output.splitlines():
        line = raw_line.strip()
        if not line.startswith("package:"):
            continue
        remote_path = line.removeprefix("package:").strip()
        if remote_path:
            apk_paths.append(remote_path)

    if not apk_paths:
        raise ExtractorError(
            f"No APK paths returned by 'pm path' for package '{package_name}'."
        )

    base_path = next(
        (path for path in apk_paths if path.endswith("/base.apk")),
        apk_paths[0],
    )

    if not base_path.startswith("/") or not base_path.endswith(".apk"):
        raise ExtractorError(
            f"Unexpected remote APK path returned for '{package_name}': {base_path!r}"
        )

    return base_path


def pull_apk_from_device(
    package_name: str,
    dest_dir: Path,
    *,
    timeout: int = DEFAULT_ADB_TIMEOUT_SECONDS,
) -> Path:
    """Pull the base APK for an installed Android package from a connected device via adb."""
    validated_package = validate_package_name(package_name)
    adb_bin = ensure_tool_available("adb")

    pm_result = _run_command(
        [adb_bin, "shell", "pm", "path", validated_package],
        timeout=timeout,
    )
    remote_apk_path = _extract_base_apk_path(pm_result.stdout, validated_package)

    dest_dir.mkdir(parents=True, exist_ok=True)
    local_apk_path = dest_dir / f"{validated_package}.apk"

    _run_command(
        [adb_bin, "pull", remote_apk_path, str(local_apk_path)],
        timeout=timeout,
    )

    if not local_apk_path.is_file():
        raise ExtractorError(
            f"ADB pull completed but expected APK was not found at: {local_apk_path}"
        )

    return local_apk_path


def decompile_apk(
    apk_path: Path,
    output_dir: Path,
    *,
    timeout: int = DEFAULT_APKTOOL_TIMEOUT_SECONDS,
) -> Path:
    """Decompile an APK with apktool and return the path to AndroidManifest.xml."""
    if not apk_path.is_file():
        raise ExtractorError(f"APK file not found or not a regular file: {apk_path}")
    if apk_path.suffix.lower() != ".apk":
        raise ExtractorError(
            f"Invalid APK file extension for '{apk_path}'. Expected '.apk'."
        )

    apktool_bin = ensure_tool_available("apktool")
    output_dir.parent.mkdir(parents=True, exist_ok=True)

    _run_command(
        [apktool_bin, "d", "-f", str(apk_path), "-o", str(output_dir)],
        timeout=timeout,
    )

    manifest_path = output_dir / "AndroidManifest.xml"
    if not manifest_path.is_file():
        raise DecompilationError(
            f"Decompilation completed but AndroidManifest.xml was not generated in: {output_dir}"
        )

    return manifest_path
