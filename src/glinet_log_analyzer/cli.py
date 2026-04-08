from __future__ import annotations

import json
import os
from pathlib import Path

import typer
import uvicorn

from .analyzer import analyze_documents
from .ingest import load_documents_from_path
from .reporting import entries_to_csv, filter_entries
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

    typer.echo(f"Analyzed {file}")
    typer.echo(f"Sources loaded: {len(result.source_counts)}")
    typer.echo(f"Total entries: {len(result.entries)}")
    typer.echo(f"Filtered entries: {len(filtered_entries)}")
    typer.echo("Severity counts:")
    for severity, count in result.severity_counts.most_common():
        typer.echo(f"  {severity}: {count}")
    typer.echo("Top categories:")
    for category, count in result.category_counts.most_common(5):
        typer.echo(f"  {category}: {count}")
    typer.echo("Top signals:")
    for signal, count in result.signal_counts.most_common(8):
        typer.echo(f"  {signal}: {count}")
    typer.echo("Top sources:")
    for source, count in result.source_counts.most_common(5):
        typer.echo(f"  {source}: {count}")
    typer.echo("Operational timeline:")
    for entry in result.timeline[:12]:
        signal_text = ", ".join(entry.signals) if entry.signals else "uncategorized"
        prefix = f"{entry.timestamp} " if entry.timestamp else ""
        source_label = f"[{entry.source}] " if entry.source else ""
        typer.echo(f"  line {entry.line_number}: {source_label}{prefix}{signal_text} -> {entry.message}")
    typer.echo("Filtered entries:")
    for entry in filtered_entries[:15]:
        prefix = f"{entry.timestamp} " if entry.timestamp else ""
        source_label = f"[{entry.source}] " if entry.source else ""
        typer.echo(f"  line {entry.line_number}: {source_label}{prefix}{entry.message}")


@app.command()
def web(
    host: str = typer.Option(os.getenv("GLINET_LOG_ANALYZER_HOST", "127.0.0.1"), "--host", help="Bind address."),
    port: int = typer.Option(int(os.getenv("GLINET_LOG_ANALYZER_PORT", "8000")), "--port", help="Bind port."),
) -> None:
    """Start the local web UI."""
    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    app()
