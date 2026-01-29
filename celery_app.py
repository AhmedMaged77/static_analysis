# celery_app.py
from celery import Celery

celery = Celery(
    "static_analysis",
    broker="amqp://guest:guest@localhost:5672//",
    backend="db+postgresql://strelka:password@localhost/analysis_db",
    include=["tasks"],   # 👈 THIS IS THE KEY LINE
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)
