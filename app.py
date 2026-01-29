from fastapi import FastAPI, UploadFile, File
import shutil, uuid, os
from sqlalchemy.orm import Session
from db import SessionLocal
from model import AnalysisResult
from tasks import analyze_file_task
from utils import sha256sum

import os
from fastapi import FastAPI, UploadFile, File

app = FastAPI()



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

