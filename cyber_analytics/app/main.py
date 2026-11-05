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

# In Starlette, middlewares execute in reverse order of addition.
# Adding SecurityEventMiddleware first, then CORSMiddleware last ensures
# CORSMiddleware is the OUTERMOST layer, properly handling OPTIONS preflights
# and attaching CORS headers to all responses.
app.add_middleware(SecurityEventMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(graph.router)
app.include_router(vms_hooks.router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "cyber-analytics"}
