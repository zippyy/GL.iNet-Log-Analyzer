from __future__ import annotations

import json
import os
from pathlib import Path

import typer
import uvicorn

from .analyzer import analyze_documents
from .ingest import load_documents_from_path
from .reporting import entries_to_csv, filter_entries, format_text_report
from .web import create_app

app = typer.Typer(no_args_is_help=True, help="Analyze GL.iNet router logs from the CLI or web UI.")


@app.command()
def analyze(
    file: Path = typer.Argument(..., exists=True, readable=True, resolve_path=True, help="Log file to analyze."),
    output: str = typer.Option("text", "--output", "-o", help="Output format: text or json."),
    severity: str | None = typer.Option(None, help="Only include entries with this severity."),
    category: str | None = typer.Option(None, help="Only include entries in this category."),
    signal: str | None = typer.Option(None, help="Only include entries with this signal."),
    source_contains: str | None = typer.Option(None, help="Only include entries whose source path contains this text."),
    query: str | None = typer.Option(None, "--query", "-q", help="Free-text filter on messages and raw lines."),
    export: Path | None = typer.Option(None, help="Optional path to export filtered entries as JSON or CSV."),
) -> None:
    """Analyze a router log file."""
    result = analyze_documents(load_documents_from_path(file))
    filtered_entries = filter_entries(
        result.entries,
        severity=severity,
        category=category,
        signal=signal,
        source_contains=source_contains,
        query=query,
    )

    if export:
        suffix = export.suffix.lower()
        if suffix == ".json":
            export.write_text(json.dumps([entry.to_dict() for entry in filtered_entries], indent=2), encoding="utf-8")
        elif suffix == ".csv":
            export.write_text(entries_to_csv(filtered_entries), encoding="utf-8")
        else:
            raise typer.BadParameter("Export path must end in .json or .csv.")

    if output == "json":
        payload = result.to_dict()
        payload["filtered_entries"] = [entry.to_dict() for entry in filtered_entries]
        typer.echo(json.dumps(payload, indent=2))
        return
    if output != "text":
        raise typer.BadParameter("Output must be either 'text' or 'json'.")

    typer.echo(format_text_report(result, filtered_entries, file_label=str(file)))


@app.command()
def web(
    host: str = typer.Option(os.getenv("GLINET_LOG_ANALYZER_HOST", "127.0.0.1"), "--host", help="Bind address."),
    port: int = typer.Option(int(os.getenv("GLINET_LOG_ANALYZER_PORT", "8000")), "--port", help="Bind port."),
) -> None:
    """Start the local web UI."""
    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    app()
