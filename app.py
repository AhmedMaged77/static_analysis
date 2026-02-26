from fastapi import FastAPI, UploadFile, File
import shutil, uuid, os
from sqlalchemy.orm import Session
from db import SessionLocal
from model import AnalysisResult
from tasks import analyze_file_task
from utils import sha256sum, fetch_url_content
from scoring import compute_url_score

import os
import validators
from urllib.parse import urlparse
from pydantic import BaseModel, field_validator
from fastapi import FastAPI, UploadFile, File, HTTPException

app = FastAPI(
    title="Static Analysis API",
    description="File and URL static analysis with scoring and verdict generation",
)



BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)



@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_FOLDER, f"{file_id}_{file.filename}")

    print("Saving to:", file_path)

    with open(file_path, "wb") as buffer:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            buffer.write(chunk)

    print("File saved, size:", os.path.getsize(file_path))

    file_hash = sha256sum(file_path)

    # Check DB
    db: Session = SessionLocal()
    result = db.query(AnalysisResult).filter_by(sha256=file_hash).first()
    
    if result:
        db.close()
        os.remove(file_path)
        return {
            "message": "File already analyzed",
            "task_id": None,
            "sha256": file_hash,
            "score": result.score,
            "verdict": result.verdict,
            "reasons": result.reasons
        }

    # Enqueue Celery task
    task = analyze_file_task.delay(file_path, file_hash, file.filename)
    db.close()

    return {"message": "File queued for analysis", "task_id": task.id, "sha256": file_hash}


@app.get("/status/{task_id}")
def get_status(task_id: str):
    from celery.result import AsyncResult
    from celery_app import celery
    result = AsyncResult(task_id, app=celery)
    return {
        "task_id": task_id,
        "state": result.state,
        "result": result.result if result.successful() else None
    }



# URL Analysis Endpoint

class URLRequest(BaseModel):
    """Request body for the /analyze-url endpoint."""
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL must not be empty")
        # Ensure scheme is present
        if not v.startswith(("http://", "https://")):
            v = "http://" + v
        if not validators.url(v):
            raise ValueError(f"Invalid URL: {v}")
        return v


@app.post("/analyze-url")
async def analyze_url(body: URLRequest):
    """
    Perform multi-layer static and content-based analysis of a URL.

    Analysis pipeline:
      1. URL structure analysis (length, chars, TLD, homograph …)
      2. Domain intelligence (WHOIS age, DNS records)
      3. Content analysis (HTML iframes, obfuscated JS, phishing forms …)
      4. Threat intelligence (VirusTotal URL + domain lookup)
      5. Risk scoring engine (weighted aggregation)
      6. Explainable verdict generation

    Returns:
      - score   : integer risk score
      - verdict : SAFE | SUSPICIOUS | MALICIOUS
      - reasons : list of triggered indicators
    """
    url = body.url

    try:
        # Fetch page content asynchronously (with timeout)
        content = await fetch_url_content(url, timeout=5.0)

        # Run the scoring engine
        result = compute_url_score(
            url=url,
            html_body=content.get("body", ""),
            redirect_count=content.get("redirect_count", 0),
            fetch_error=content.get("error"),
        )

        # Attach fetch metadata for transparency
        result["final_url"] = content.get("final_url", url)
        result["http_status"] = content.get("status_code")
        result["redirect_count"] = content.get("redirect_count", 0)

        return result

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(exc)}",
        )

