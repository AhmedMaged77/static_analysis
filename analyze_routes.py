import os
import uuid

from fastapi import APIRouter, File, UploadFile, HTTPException
from sqlalchemy.orm import Session

from db import SessionLocal
from model import AnalysisResult
from scoring_v2 import compute_score
from static_analyzer import analyze_file
from utils import sha256sum

router = APIRouter()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@router.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    """
    Single-step file analysis endpoint.
    Uploads the file, runs full static analysis in-process,
    persists the result, and returns everything in one response.
    No Celery. No Strelka. No polling.
    """
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_FOLDER, f"{file_id}_{file.filename}")

    try:
        # ── Save uploaded file ───────────────────────────────────────────
        with open(file_path, "wb") as buffer:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                buffer.write(chunk)

        file_hash = sha256sum(file_path)
        db: Session = SessionLocal()

        try:
            # ── SHA256 deduplication cache ───────────────────────────────
            existing = db.query(AnalysisResult).filter_by(sha256=file_hash).first()
            if existing:
                return {
                    "message": "File already analyzed (cached result)",
                    "sha256": file_hash,
                    "score": existing.score,
                    "verdict": existing.verdict,
                    "reasons": existing.reasons,
                }

            # ── Run in-process static analysis ───────────────────────────
            analysis_json = analyze_file(file_path)
            score, verdict, reasons = compute_score(analysis_json, file.filename)

            # ── Persist to database ──────────────────────────────────────
            entry = AnalysisResult(
                sha256=file_hash,
                file_name=file.filename,
                strelka_output=analysis_json,
                score=score,
                verdict=verdict,
                reasons=reasons,
            )
            db.add(entry)
            db.commit()

        finally:
            db.close()

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

    return {
        "message": "Analysis complete",
        "sha256": file_hash,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
    }
