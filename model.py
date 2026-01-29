from sqlalchemy import Column, String, Integer, JSON, DateTime
from datetime import datetime
from db import Base

class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    sha256 = Column(String(64), primary_key=True, index=True)
    file_name = Column(String(255))
    strelka_output = Column(JSON)
    score = Column(Integer)
    verdict = Column(String(50))
    reasons = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
