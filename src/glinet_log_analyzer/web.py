from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from .analyzer import AnalysisResult, analyze_documents
from .ingest import load_documents_from_bytes
from .reporting import build_filter_options, entries_to_csv, filter_entries
from .storage import load_report, save_report

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
            context={"result": None, "error": None, "filters": {}, "filter_options": {}, "filtered_entries": [], "report_id": None},
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
    }
