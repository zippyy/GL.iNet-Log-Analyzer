from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from .analyzer import AnalysisResult, analyze_documents
from .ingest import load_documents_from_bytes
from .reporting import build_filter_options, build_narrative_timeline, entries_to_csv, filter_entries, generate_triage_notes, generate_verdict, CATEGORY_LABELS, SEVERITY_LABELS, SIGNAL_LABELS
from .storage import list_reports, load_report, save_report
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def create_app() -> FastAPI:
    app = FastAPI(title="GL.iNet Log Analyzer")

    @app.get("/healthz")
    async def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"result": None, "error": None, "filters": {}, "filter_options": {}, "filtered_entries": [], "report_id": None, "signal_labels": SIGNAL_LABELS, "category_labels": CATEGORY_LABELS, "severity_labels": SEVERITY_LABELS},
        )

    @app.post("/", response_class=HTMLResponse)
    async def analyze_upload(request: Request, log_file: UploadFile = File(...)) -> HTMLResponse:
        raw = await log_file.read()
        documents = load_documents_from_bytes(log_file.filename or "upload.log", raw)
        result = analyze_documents(documents)
        report_id = str(uuid4())
        save_report(report_id, log_file.filename or "upload.log", result)
        return templates.TemplateResponse(request=request, name="index.html", context=_build_context(request, report_id, result))

    @app.get("/reports/{report_id}", response_class=HTMLResponse)
    async def view_report(
        request: Request,
        report_id: str,
        severity: str | None = None,
        category: str | None = None,
        signal: str | None = None,
        source: str | None = None,
        q: str | None = None,
    ) -> HTMLResponse:
        stored = load_report(report_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Report not found")
        result = stored["result"]
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context=_build_context(request, report_id, result, severity=severity, category=category, signal=signal, source=source, query=q),
        )

    @app.get("/reports/{report_id}.json")
    async def download_json(
        report_id: str,
        severity: str | None = None,
        category: str | None = None,
        signal: str | None = None,
        source: str | None = None,
        q: str | None = None,
    ) -> PlainTextResponse:
        stored = load_report(report_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Report not found")
        result = stored["result"]
        filtered_entries = filter_entries(result.entries, severity=severity, category=category, signal=signal, source_contains=source, query=q)
        payload = {
            "report_id": report_id,
            "filename": stored["filename"],
            "summary": result.to_dict()["summary"],
            "filtered_entries": [entry.to_dict() for entry in filtered_entries],
        }
        return PlainTextResponse(json.dumps(payload, indent=2), media_type="application/json")

    @app.get("/reports/{report_id}.csv")
    async def download_csv(
        report_id: str,
        severity: str | None = None,
        category: str | None = None,
        signal: str | None = None,
        source: str | None = None,
        q: str | None = None,
    ) -> PlainTextResponse:
        stored = load_report(report_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Report not found")
        result = stored["result"]
        filtered_entries = filter_entries(result.entries, severity=severity, category=category, signal=signal, source_contains=source, query=q)
        return PlainTextResponse(entries_to_csv(filtered_entries), media_type="text/csv")

    @app.get("/reports/{report_id}.html")
    async def download_html(
        request: Request,
        report_id: str,
    ) -> HTMLResponse:
        stored = load_report(report_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Report not found")
        result = stored["result"]
        context = _build_context(request, report_id, result)
        context.pop("request", None)
        html = templates.TemplateResponse(
            request=request, name="index.html", context=context
        )
        return html

    @app.get("/reports", response_class=HTMLResponse)
    async def report_history(request: Request) -> HTMLResponse:
        reports = list_reports()
        return HTMLResponse(content=_render_history_page(reports, request))

    return app


def _build_context(
    request: Request,
    report_id: str,
    result: AnalysisResult,
    *,
    severity: str | None = None,
    category: str | None = None,
    signal: str | None = None,
    source: str | None = None,
    query: str | None = None,
) -> dict[str, object]:
    stored = load_report(report_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Report not found")
    filtered_entries = filter_entries(
        result.entries,
        severity=severity,
        category=category,
        signal=signal,
        source_contains=source,
        query=query,
    )
    return {
        "request": request,
        "result": result.to_dict(),
        "error": None,
        "filename": stored["filename"],
        "report_id": report_id,
        "filters": {
            "severity": severity or "",
            "category": category or "",
            "signal": signal or "",
            "source": source or "",
            "query": query or "",
        },
        "filter_options": build_filter_options(result),
        "filtered_entries": [entry.to_dict() for entry in filtered_entries[:100]],
        "filtered_count": len(filtered_entries),
        "signal_labels": SIGNAL_LABELS,
        "category_labels": CATEGORY_LABELS,
        "severity_labels": SEVERITY_LABELS,
        "verdict": generate_verdict(result),
        "triage_notes": generate_triage_notes(result),
        "narrative_timeline": build_narrative_timeline(result),
    }


def _render_history_page(reports: list[dict[str, object]], request: Request) -> str:
    rows = ""
    for r in reports:
        rid = r["report_id"]
        fname = r["filename"]
        lines = r["total_lines"]
        created = datetime.fromtimestamp(float(r["created"])).strftime("%Y-%m-%d %H:%M")
        rows += f"""<tr>
            <td><a href="/reports/{rid}">{fname}</a></td>
            <td>{lines}</td>
            <td>{created}</td>
            <td><tt style="font-size:0.75rem;color:var(--muted)">{rid[:8]}</tt></td>
            <td>
              <a href="/reports/{rid}.json">JSON</a> ·
              <a href="/reports/{rid}.csv">CSV</a> ·
              <a href="/reports/{rid}.html">HTML</a>
            </td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Report History — GL.iNet Log Analyzer</title>
  <style>
    :root {{ --bg:#f4efe8;--panel:rgba(255,252,248,0.92);--ink:#1f1d1a;--muted:#70665d;--accent:#0f766e;--line:#d8cfc6;--card:rgba(255,255,255,0.68); }}
    [data-theme="dark"] {{ --bg:#12100e;--panel:rgba(28,26,23,0.94);--ink:#e8e4df;--muted:#9d9388;--accent:#2dd4bf;--line:#3d3832;--card:rgba(35,32,29,0.75); }}
    * {{ box-sizing:border-box; }} body {{ margin:0;font-family:Georgia,serif;color:var(--ink);background:var(--bg);min-height:100vh; }}
    main {{ max-width:900px;margin:0 auto;padding:48px 20px 64px; }}
    h1 {{ font-size:2rem;margin:0 0 8px; }} a {{ color:var(--accent);text-decoration:none;font-weight:600; }}
    .panel {{ background:var(--panel);border:1px solid var(--line);border-radius:22px;padding:24px;backdrop-filter:blur(8px); }}
    .topbar {{ display:flex;justify-content:space-between;align-items:center;margin-bottom:28px; }}
    table {{ width:100%;border-collapse:collapse;font-family:'Segoe UI',sans-serif;margin-top:12px; }}
    th,td {{ text-align:left;border-bottom:1px solid var(--line);padding:12px 10px; }}
    th {{ font-size:0.78rem;text-transform:uppercase;color:var(--muted);letter-spacing:0.06em; }}
    .empty {{ text-align:center;color:var(--muted);padding:40px;font-family:'Segoe UI',sans-serif; }}
  </style>
</head>
<body>
  <main>
    <div class="topbar">
      <h1>📋 Report History</h1>
      <a href="/">← Back to analyzer</a>
    </div>
    <section class="panel">
      {"<table><thead><tr><th>File</th><th>Entries</th><th>Analyzed</th><th>ID</th><th>Export</th></tr></thead><tbody>" + rows + "</tbody></table>" if rows else '<div class="empty">No reports yet. <a href="/">Upload a log file</a> to get started.</div>'}
    </section>
  </main>
</body>
</html>"""
