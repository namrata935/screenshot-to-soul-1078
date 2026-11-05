from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import SessionLocal, engine
from app.middleware import SecurityEventMiddleware
from app.models import Base
from app.routers import alerts, events, graph, vms_hooks
from app.seed import seed_database_if_empty


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure tables exist
    Base.metadata.create_all(bind=engine)
    # Seed initial data if empty
    db = SessionLocal()
    try:
        seed_database_if_empty(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="Secure VMS Cybersecurity Analytics",
    description="Monitors the surveillance platform itself (identity, access, camera health).",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",
        "http://localhost:5173",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityEventMiddleware)

app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(graph.router)
app.include_router(vms_hooks.router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "cyber-analytics"}
