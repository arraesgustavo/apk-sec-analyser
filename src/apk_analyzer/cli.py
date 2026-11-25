"""Command-line interface entrypoint for apk-sec-analyzer."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

import typer

MODEL_ENV_VAR = "APK_ANALYZER_MODEL"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_OUTPUT = Path("report.md")

app = typer.Typer(
    name="apk-analyzer",
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


def _fail(message: str, exit_code: int = 2) -> None:
    """Emit a formatted error message to stderr and terminate with non-zero status."""
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code=exit_code)


def _validate_params(
    apk: Path | None,
    adb_package: str | None,
    output: Path,
    model: str,
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
    if not cleaned_model:
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
        )

    assert cleaned_package is not None
    if not cleaned_package:
        _fail("Option --adb-package cannot be empty.")

    return AnalysisParams(
        source_type="adb",
        target=cleaned_package,
        output=output,
        model=cleaned_model,
    )


def _print_summary(params: AnalysisParams) -> None:
    """Print a structured summary of validated pipeline parameters."""
    source_label = "Local APK" if params.source_type == "apk" else "ADB Package"
    typer.echo("Pipeline Configuration")
    typer.echo(f"  Source : {source_label}")
    typer.echo(f"  Target : {params.target}")
    typer.echo(f"  Output : {params.output}")
    typer.echo(f"  Model  : {params.model}")


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
) -> None:
    """Validate CLI inputs and display the resolved analysis configuration."""
    params = _validate_params(
        apk=apk,
        adb_package=adb_package,
        output=output,
        model=model,
    )
    _print_summary(params)


def main() -> None:
    """Entrypoint registered in pyproject.toml for the apk-analyzer CLI."""
    app()


if __name__ == "__main__":
    main()
