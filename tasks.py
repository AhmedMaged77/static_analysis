from celery_app import celery
from db import SessionLocal
from model import AnalysisResult
from file_scoring import compute_score
import subprocess, json, os
from dotenv import load_dotenv

load_dotenv()

Strelka_Dir = os.getenv("Strelka_Dir")

@celery.task(name="tasks.analyze_file_task")
def analyze_file_task(file_path, file_hash, file_name):
    """
    Celery task:
    1. Runs Strelka OneShot
    2. Applies scoring logic
    3. Saves result in PostgreSQL
    """
    print(file_path)
    try:
        strelka_cmd = [
            Strelka_Dir,  
            "-f", file_path,
            "-s", "172.18.0.1:57314",
            "-l", "-"
        ]
        result = subprocess.run(strelka_cmd, capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split("\n")
        strelka_json = [json.loads(line) for line in lines if line.strip()]

        # Apply scoring logic  
        score, verdict, reasons = compute_score(strelka_json,file_path)

        # Save to PostgreSQL
        db = SessionLocal()
        entry = AnalysisResult(
            sha256=file_hash,
            file_name=file_name,
            strelka_output=strelka_json,
            score=score,
            verdict=verdict,
            reasons=reasons
        )
        db.add(entry)
        db.commit()
        db.close()

    except subprocess.CalledProcessError as e:
        print(f"Error running Strelka: {e}")
        return {"error": "Strelka failed"}

    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

    return {"score": score, "verdict": verdict, "reasons": reasons}
