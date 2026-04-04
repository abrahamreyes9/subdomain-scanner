"""
main.py — FastAPI web server for the subdomain scanner.
"""

import asyncio
import json
import queue
import threading
import uuid
import re
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

from scanner import run_scan

load_dotenv()
app = FastAPI(title="Subdomain Scanner")
app.mount("/static", StaticFiles(directory="static"), name="static")

# In-memory store: scan_id → dict with q and accessed state
_scans: dict[str, dict] = {}


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("static/index.html", encoding="utf-8") as f:
        return f.read()


class ScanRequest(BaseModel):
    domain: str


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    domain = req.domain.strip().lower().rstrip(".")
    
    # Basic domain regex validation to prevent injection and invalid inputs
    domain_regex = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"
    if not domain or not re.match(domain_regex, domain):
        raise HTTPException(400, "Invalid domain")

    scan_id = str(uuid.uuid4())
    q: queue.Queue = queue.Queue(maxsize=2000)
    _scans[scan_id] = {"q": q, "accessed": False, "created_at": time.time()}

    # Cleanup stale unaccessed scans to prevent memory leaks
    import time as _time
    now = _time.time()
    stale = [k for k, v in list(_scans.items()) if not v["accessed"] and now - v["created_at"] > 60]
    for k in stale:
        _scans.pop(k, None)

    shodan_key = os.getenv("SHODAN_API_KEY")
    thread = threading.Thread(target=run_scan, args=(domain, q, 100, 50, shodan_key), daemon=True)
    thread.start()

    return {"scan_id": scan_id}


@app.get("/api/stream/{scan_id}")
async def stream_results(scan_id: str):
    session = _scans.get(scan_id)
    if not session:
        raise HTTPException(404, "Scan not found")
        
    session["accessed"] = True
    q = session["q"]

    async def generate():
        loop = asyncio.get_event_loop()
        try:
            while True:
                # Block in a thread so we don't freeze the async event loop
                item = await loop.run_in_executor(None, q.get)
                if item is None:
                    # Sentinel — scan finished
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    break
                yield f"data: {json.dumps(item)}\n\n"
        finally:
            _scans.pop(scan_id, None)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",       # disable Nginx buffering
            "Access-Control-Allow-Origin": "*",
        },
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
