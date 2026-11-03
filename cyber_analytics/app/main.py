from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.middleware import SecurityEventMiddleware
from app.routers import events, vms_hooks

app = FastAPI(
    title="Secure VMS Cybersecurity Analytics",
    description="Monitors the surveillance platform itself (identity, access, camera health).",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://localhost:5173", "http://127.0.0.1:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityEventMiddleware)

app.include_router(events.router)
app.include_router(vms_hooks.router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "cyber-analytics"}
