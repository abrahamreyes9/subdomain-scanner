"""
main.py — FastAPI web server for the subdomain scanner.
"""

import asyncio
import json
import queue
import threading
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from scanner import run_scan

app = FastAPI(title="Subdomain Scanner")
app.mount("/static", StaticFiles(directory="static"), name="static")

# In-memory store: scan_id → queue
_scans: dict[str, queue.Queue] = {}


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
    if not domain or "." not in domain:
        raise HTTPException(400, "Invalid domain")

    scan_id = str(uuid.uuid4())
    q: queue.Queue = queue.Queue()
    _scans[scan_id] = q

    thread = threading.Thread(target=run_scan, args=(domain, q), daemon=True)
    thread.start()

    return {"scan_id": scan_id}


@app.get("/api/stream/{scan_id}")
async def stream_results(scan_id: str):
    q = _scans.get(scan_id)
    if not q:
        raise HTTPException(404, "Scan not found")

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
