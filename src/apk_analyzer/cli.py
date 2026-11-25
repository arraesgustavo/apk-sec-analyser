"""Command-line interface entrypoint for apk-sec-analyser."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tempfile
from typing import Annotated, Literal

import typer

from apk_analyzer.extractor import (
    ExtractorError,
    decompile_apk,
    pull_apk_from_device,
)
from apk_analyzer.llm_client import (
    DEFAULT_LLM_MODEL,
    LLM_MODEL_ENV,
    LLMAnalysisError,
    LLMAnalyzerClient,
)
from apk_analyzer.manifest_parser import ManifestParseError, parse_manifest
from apk_analyzer.reporter import (
    render_markdown_report,
    render_static_only_report,
    save_report,
)

MODEL_ENV_VAR = LLM_MODEL_ENV
DEFAULT_MODEL = DEFAULT_LLM_MODEL
DEFAULT_OUTPUT = Path("report.md")

app = typer.Typer(
    name="apk-sec-analyser",
    help="Android APK static security analyzer with optional LLM-assisted triage.",
    add_completion=False,
)


@dataclass(frozen=True)
class AnalysisParams:
    """Validated CLI parameters for the analysis pipeline."""

    source_type: Literal["apk", "adb"]
    target: str
    output: Path
    model: str
    no_llm: bool = False


def _fail(message: str, exit_code: int = 2) -> None:
    """Emit a formatted error message to stderr and terminate with non-zero status."""
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code=exit_code)


def _validate_params(
    apk: Path | None,
    adb_package: str | None,
    output: Path,
    model: str,
    no_llm: bool,
) -> AnalysisParams:
    """Validate mutually exclusive input sources and file constraints."""
    cleaned_package = adb_package.strip() if adb_package is not None else None
    has_apk = apk is not None
    has_adb = cleaned_package is not None

    if has_apk and has_adb:
        _fail("Options --apk and --adb-package are mutually exclusive. Provide only one.")

    if not has_apk and not has_adb:
        _fail("You must provide either --apk <path> or --adb-package <package>.")

    cleaned_model = model.strip()
    if not no_llm and not cleaned_model:
        _fail(f"Model name cannot be empty (set --model or {MODEL_ENV_VAR}).")

    if has_apk and apk is not None:
        if not apk.exists():
            _fail(f"APK file not found: {apk}", exit_code=1)
        if not apk.is_file():
            _fail(f"APK path is not a regular file: {apk}", exit_code=1)
        if apk.suffix.lower() != ".apk":
            _fail(
                f"Invalid file extension '{apk.suffix or '<none>'}' for '{apk}'. Expected a '.apk' file.",
                exit_code=1,
            )
        return AnalysisParams(
            source_type="apk",
            target=str(apk.resolve()),
            output=output,
            model=cleaned_model,
            no_llm=no_llm,
        )

    assert cleaned_package is not None
    if not cleaned_package:
        _fail("Option --adb-package cannot be empty.")

    return AnalysisParams(
        source_type="adb",
        target=cleaned_package,
        output=output,
        model=cleaned_model,
        no_llm=no_llm,
    )


def _run_pipeline(params: AnalysisParams) -> tuple[str, int, Path]:
    """Execute the end-to-end extraction, manifest parsing, triage, and reporting pipeline."""
    with tempfile.TemporaryDirectory(prefix="apk-sec-analyser-") as tmp_dir:
        work_dir = Path(tmp_dir)

        if params.source_type == "adb":
            typer.echo(f"Pulling APK for package '{params.target}' via adb...")
            apk_path = pull_apk_from_device(params.target, work_dir / "apk")
        else:
            apk_path = Path(params.target)

        typer.echo(f"Decompiling '{apk_path.name}' with apktool...")
        manifest_path = decompile_apk(apk_path, work_dir / "decompiled")

        typer.echo("Analyzing AndroidManifest.xml...")
        manifest_analysis = parse_manifest(manifest_path)

    package_name = (
        manifest_analysis.package_name
        or (params.target if params.source_type == "adb" else Path(params.target).stem)
    )
    raw_findings = [finding.to_dict() for finding in manifest_analysis.findings]

    if params.no_llm:
        report_markdown = render_static_only_report(package_name, raw_findings)
        findings_count = len(raw_findings)
    else:
        typer.echo(f"Running LLM triage with model '{params.model}'...")
        llm_client = LLMAnalyzerClient(model=params.model)
        security_report = llm_client.analyze_manifest_findings(
            package_name=package_name,
            findings=raw_findings,
        )
        report_markdown = render_markdown_report(security_report)
        findings_count = len(security_report.findings)

    saved_path = save_report(report_markdown, params.output)
    return package_name, findings_count, saved_path


def _print_result_summary(
    package_name: str,
    findings_count: int,
    report_path: Path,
    *,
    no_llm: bool,
) -> None:
    """Print a concise summary of the completed analysis."""
    mode_label = "Static-only (--no-llm)" if no_llm else "LLM-assisted"
    typer.echo("Analysis Complete")
    typer.echo(f"  Package  : {package_name}")
    typer.echo(f"  Mode     : {mode_label}")
    typer.echo(f"  Findings : {findings_count}")
    typer.echo(f"  Report   : {report_path}")


@app.command()
def analyze(
    apk: Annotated[
        Path | None,
        typer.Option(
            "--apk",
            help="Path to a local .apk file to analyze.",
            show_default=False,
        ),
    ] = None,
    adb_package: Annotated[
        str | None,
        typer.Option(
            "--adb-package",
            help="Android package name to pull via adb (e.g. com.example.app).",
            show_default=False,
        ),
    ] = None,
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            help="Path for the generated Markdown security report.",
        ),
    ] = DEFAULT_OUTPUT,
    model: Annotated[
        str,
        typer.Option(
            "--model",
            envvar=MODEL_ENV_VAR,
            help="LLM model name to use for triage.",
        ),
    ] = DEFAULT_MODEL,
    no_llm: Annotated[
        bool,
        typer.Option(
            "--no-llm",
            help="Generate a static-only Markdown report without calling the LLM.",
        ),
    ] = False,
) -> None:
    """Run the APK static security analysis pipeline and generate a Markdown report."""
    params = _validate_params(
        apk=apk,
        adb_package=adb_package,
        output=output,
        model=model,
        no_llm=no_llm,
    )

    try:
        package_name, findings_count, saved_path = _run_pipeline(params)
    except ExtractorError as exc:
        _fail(f"APK extraction or decompilation failed: {exc}", exit_code=1)
    except ManifestParseError as exc:
        _fail(f"Manifest parsing failed: {exc}", exit_code=1)
    except LLMAnalysisError as exc:
        _fail(f"LLM analysis failed: {exc}", exit_code=1)
    except OSError as exc:
        _fail(f"Failed to save report to '{params.output}': {exc}", exit_code=1)

    _print_result_summary(
        package_name=package_name,
        findings_count=findings_count,
        report_path=saved_path,
        no_llm=params.no_llm,
    )


def main() -> None:
    """Entrypoint registered in pyproject.toml for the apk-sec-analyser CLI."""
    app()


if __name__ == "__main__":
    main()
