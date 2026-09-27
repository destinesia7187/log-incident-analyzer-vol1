"""Command line entry points. No command performs external messaging."""

from __future__ import annotations

import functools
import json
from pathlib import Path

import typer

from .common import LiaError, terminal_safe, write_json
from .config import Config, load_config, parse_model
from .demo import recovery_context, story, write_input
from .evaluation import replay as replay_suite
from .pipeline import analyze as analyze_run
from .pipeline import compare as compare_runs
from .pipeline import read_run, update_case
from .reporting import markdown
from .rules import DEPRECATED, load_rules

app = typer.Typer(
    help="Offline, evidence-based SOC L1 log incident analysis.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
case_app = typer.Typer(help="Review cases locally.")
app.add_typer(case_app, name="case")


def handled(fn):
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except LiaError as exc:
            typer.echo(json.dumps({"error": exc.code}), err=True)
            raise typer.Exit(exc.exit_code) from None
        except (OSError, ValueError) as exc:
            typer.echo(json.dumps({"error": "io_or_value_error", "type": type(exc).__name__}), err=True)
            raise typer.Exit(4) from None
        except KeyboardInterrupt:
            raise typer.Exit(130) from None

    return wrapped


def emit(value):
    typer.echo(terminal_safe(json.dumps(value, ensure_ascii=False, sort_keys=True)))


@app.command("validate-config")
@handled
def validate_config(config: Path = typer.Option(...)):
    load_config(config)
    emit({"valid": True})


@app.command("validate-rules")
@handled
def validate_rule_command(rules: Path | None = typer.Option(None)):
    values = load_rules(rules)
    emit(
        {
            "valid": True,
            "count": len(values),
            "warnings": [
                r["id"] + ":deprecated_technique"
                for r in values
                if any(m["technique_id"] in DEPRECATED for m in r["attack"])
            ],
        }
    )


@app.command("analyze")
@handled
def analyze(
    manifest: Path = typer.Option(...),
    output: Path = typer.Option(...),
    config: Path | None = typer.Option(None),
    rules: Path | None = typer.Option(None),
    formats: str = "json,markdown",
    require_complete: bool = False,
    fail_on_alert: bool = False,
    shareable: bool = False,
    json_output: bool = typer.Option(False, "--json"),
):
    analysis, run, code = analyze_run(
        manifest,
        output,
        load_config(config),
        load_rules(rules),
        formats.split(","),
        require_complete,
        fail_on_alert,
        shareable,
    )
    emit(
        {
            "state": run["state"],
            "cases": len(analysis["cases"]),
            "alerts": len(analysis["alerts"]),
            "output": str(output),
            "analysis_hash": run["analysis_hash"],
        }
    )
    raise typer.Exit(code)


@app.command("demo")
@handled
def demo(
    output: Path = typer.Option(...),
    variant: str = "attack",
    json_output: bool = typer.Option(False, "--json"),
):
    if output.exists():
        raise LiaError("existing_output")
    manifest = write_input(output.parent / ("demo-input-" + variant), story(variant))
    config = parse_model(Config, {"context": [recovery_context()]}) if variant == "recovery" else Config()
    analysis, run, code = analyze_run(manifest, output, config, formats=["json", "markdown", "html"])
    emit(
        {
            "state": run["state"],
            "cases": len(analysis["cases"]),
            "alerts": len(analysis["alerts"]),
            "report": str(output / "report.html"),
        }
    )
    raise typer.Exit(code)


@app.command("quality")
@handled
def quality(
    run: Path = typer.Option(...), format: str = "json", json_output: bool = typer.Option(False, "--json")
):
    if format != "json":
        raise LiaError("unsupported_format")
    emit({"rules": read_run(run)["quality"]})


@app.command("explain")
@handled
def explain(
    run: Path = typer.Option(...),
    case: str = typer.Option(...),
    format: str = "markdown",
    json_output: bool = typer.Option(False, "--json"),
):
    analysis = read_run(run)
    found = next((c for c in analysis["cases"] if c["id"] == case), None)
    if found is None:
        raise LiaError("unknown_case")
    if format == "json" or json_output:
        emit(found)
    elif format == "markdown":
        analysis["cases"] = [found]
        typer.echo(terminal_safe(markdown(analysis)))
    else:
        raise LiaError("unsupported_format")


@case_app.command("set-status")
@handled
def set_status(
    run: Path = typer.Option(...),
    case: str = typer.Option(...),
    status: str = typer.Option(...),
    analyst: str = typer.Option(...),
    reason: str = "",
    verdict: str | None = None,
):
    emit(update_case(run, case, analyst, status=status, reason=reason, verdict=verdict))


@case_app.command("add-note")
@handled
def add_note(
    run: Path = typer.Option(...),
    case: str = typer.Option(...),
    text: str = typer.Option(...),
    analyst: str = typer.Option(...),
):
    emit(update_case(run, case, analyst, note=text))


@app.command("compare")
@handled
def compare(
    baseline: Path = typer.Option(...), candidate: Path = typer.Option(...), output: Path = typer.Option(...)
):
    result = compare_runs(read_run(baseline), read_run(candidate))
    if output.exists():
        raise LiaError("existing_output")
    output.mkdir(parents=True)
    write_json(output / "comparison.json", result)
    emit(result)


@app.command("replay")
@handled
def replay(suite: Path = typer.Option(...), output: Path = typer.Option(...)):
    result = replay_suite(suite, output)
    emit({"passed": result["passed"], "scenarios": len(result["scenarios"])})
    raise typer.Exit(0 if result["passed"] else 3)


@app.command("benchmark")
@handled
def benchmark(profile: Path = typer.Option(...), output: Path = typer.Option(...)):
    from .benchmark import run_benchmark

    emit(run_benchmark(profile, output))


if __name__ == "__main__":
    app()
