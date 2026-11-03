"""Thin integration hooks so the analytics middleware can sit in front of VMS actions.

These do not store video and do not replace the Flask CNN-LSTM server. They exist
so auth/video/camera calls can be logged automatically, and so other services have
a stable URL shape to proxy through or mirror.
"""

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1", tags=["vms-hooks"])


class LoginBody(BaseModel):
    username: str
    password: str
    user_id: str | None = None


class RoleBody(BaseModel):
    role: str


class HeartbeatBody(BaseModel):
    camera_id: str | None = None


@router.post("/auth/login")
def login(body: LoginBody):
    # Demo credential check only — password is never written to the event log.
    if not body.username or body.password != "correct":
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"status": "ok", "user_id": body.user_id or body.username, "username": body.username}


@router.post("/auth/logout")
def logout(x_user_id: str | None = Header(default=None, alias="X-User-Id")):
    return {"status": "ok", "user_id": x_user_id}


@router.get("/videos/{video_id}")
def view_video(video_id: str, x_role: str | None = Header(default=None, alias="X-Role")):
    if x_role == "denied":
        raise HTTPException(status_code=403, detail="Permission denied")
    return {"video_id": video_id, "action": "view"}


@router.get("/videos/{video_id}/download")
def download_video(video_id: str, x_role: str | None = Header(default=None, alias="X-Role")):
    if x_role == "denied":
        raise HTTPException(status_code=403, detail="Permission denied")
    return {"video_id": video_id, "action": "download"}


@router.post("/videos")
def upload_video(payload: dict, x_user_id: str | None = Header(default=None, alias="X-User-Id")):
    return {"status": "ok", "video_id": payload.get("video_id", "vid-new"), "user_id": x_user_id}


@router.delete("/videos/{video_id}")
def delete_video(video_id: str):
    return {"status": "ok", "video_id": video_id}


@router.post("/cameras/{camera_id}/heartbeat")
def camera_heartbeat(camera_id: str, body: HeartbeatBody | None = None):
    return {"status": "ok", "camera_id": camera_id}


@router.patch("/users/{user_id}/role")
def change_role(user_id: str, body: RoleBody):
    return {"status": "ok", "user_id": user_id, "role": body.role}
