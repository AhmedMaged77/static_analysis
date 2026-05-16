from contextlib import asynccontextmanager

from fastapi import FastAPI

import model
from db import Base, engine
from file_routes import router as file_router
from url_routes import router as url_router
from analyze_routes import router as analyze_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure newly added tables exist for already-initialized databases.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Static Analysis API",
    description="File and URL static analysis with scoring and verdict generation",
    lifespan=lifespan,
)

app.include_router(file_router)
app.include_router(url_router)
app.include_router(analyze_router)
