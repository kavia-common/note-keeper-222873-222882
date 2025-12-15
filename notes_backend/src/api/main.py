from datetime import datetime
import os
import sqlite3
import threading
import uuid
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Path, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

# ------------------------------------------------------------------------------
# FastAPI app with metadata and tags for OpenAPI
# ------------------------------------------------------------------------------
app = FastAPI(
    title="Notes API",
    description="Simple notes API with token auth. Provides CRUD for notes and basic auth endpoints.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Health", "description": "Service health and diagnostics."},
        {"name": "Auth", "description": "Authentication endpoints for obtaining and invalidating tokens."},
        {"name": "Notes", "description": "CRUD operations for notes."},
    ],
)

# ------------------------------------------------------------------------------
# CORS configuration allowing frontend running at http://localhost:3000
# ------------------------------------------------------------------------------
frontend_origin = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------------------
# Storage: Lightweight SQLite file or in-memory fallback
# ------------------------------------------------------------------------------
DB_FILE = os.getenv("SQLITE_DB_PATH", "notes.db")
USE_SQLITE = True  # Use SQLite file as requested for simplicity
_db_lock = threading.Lock()


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    with _db_lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS notes (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    owner TEXT NOT NULL
                )
                """
            )
            conn.commit()
        finally:
            conn.close()


_init_db()

# Optional seed in dev mode
if os.getenv("DEV_MODE", "true").lower() in ("1", "true", "yes", "y"):
    with _db_lock:
        conn = _get_conn()
        try:
            cur = conn.execute("SELECT COUNT(*) AS c FROM notes")
            count = cur.fetchone()["c"]
            if count == 0:
                now = datetime.utcnow().isoformat()
                seed_notes = [
                    (str(uuid.uuid4()), "Welcome", "This is your first note.", now, now, "demo"),
                    (str(uuid.uuid4()), "Second Note", "Feel free to edit or delete me.", now, now, "demo"),
                ]
                for n in seed_notes:
                    conn.execute(
                        "INSERT INTO notes (id, title, content, created_at, updated_at, owner) VALUES (?,?,?,?,?,?)",
                        n,
                    )
                conn.commit()
        finally:
            conn.close()

# ------------------------------------------------------------------------------
# Auth - very basic token system
# ------------------------------------------------------------------------------
security = HTTPBearer(auto_error=False)
# Simple in-memory token store: token -> user_id
TOKENS: Dict[str, str] = {}
TOKENS_LOCK = threading.Lock()


class LoginRequest(BaseModel):
    username: str = Field(..., description="Username for login (any string accepted in demo).")
    password: str = Field(..., description="Password for login (any string accepted in demo).")


class LoginResponse(BaseModel):
    access_token: str = Field(..., description="Bearer token to use for Authorization header.")
    token_type: str = Field(default="bearer", description="Type of token.")


class LogoutResponse(BaseModel):
    detail: str = Field(..., description="Logout status message.")


def _issue_token_for_user(user_id: str) -> str:
    token = str(uuid.uuid4())
    with TOKENS_LOCK:
        TOKENS[token] = user_id
    return token


def _revoke_token(token: str):
    with TOKENS_LOCK:
        if token in TOKENS:
            del TOKENS[token]


# PUBLIC_INTERFACE
def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> str:
    """
    Resolve the current user from the Authorization: Bearer <token> header.

    Returns:
        user_id (str): The authenticated user's ID.

    Raises:
        HTTPException 401 if token is missing or invalid.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization header missing or invalid")
    token = credentials.credentials
    with TOKENS_LOCK:
        user_id = TOKENS.get(token)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return user_id


# ------------------------------------------------------------------------------
# Schemas for Notes
# ------------------------------------------------------------------------------
class NoteBase(BaseModel):
    title: str = Field(..., description="Title of the note.")
    content: str = Field(..., description="Content/body of the note.")


class NoteCreate(NoteBase):
    pass


class NoteUpdate(BaseModel):
    title: Optional[str] = Field(None, description="Updated title of the note.")
    content: Optional[str] = Field(None, description="Updated content/body of the note.")


class Note(NoteBase):
    id: str = Field(..., description="UUID of the note.")
    created_at: datetime = Field(..., description="Creation timestamp in UTC.")
    updated_at: datetime = Field(..., description="Last update timestamp in UTC.")
    owner: str = Field(..., description="Owner (user_id) of the note.")


# ------------------------------------------------------------------------------
# Utility functions for DB operations
# ------------------------------------------------------------------------------
def _row_to_note(row: sqlite3.Row) -> Note:
    return Note(
        id=row["id"],
        title=row["title"],
        content=row["content"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        owner=row["owner"],
    )


def _fetch_note_for_owner(note_id: str, owner: str) -> Optional[Note]:
    with _db_lock:
        conn = _get_conn()
        try:
            cur = conn.execute("SELECT * FROM notes WHERE id=? AND owner=?", (note_id, owner))
            row = cur.fetchone()
            if not row:
                return None
            return _row_to_note(row)
        finally:
            conn.close()


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.get("/", tags=["Health"], summary="Health Check", description="Simple health check endpoint.")
def health_check():
    return {"message": "Healthy"}


# Auth endpoints
@app.post(
    "/auth/login",
    tags=["Auth"],
    summary="Login",
    description="Login and receive a bearer token. This is a demo endpoint that accepts any username/password and returns a token bound to user_id=demo unless username provided is used as user_id.",
    response_model=LoginResponse,
)
# PUBLIC_INTERFACE
def login(data: LoginRequest):
    """
    Login and receive an access token.

    Parameters:
        data (LoginRequest): Contains username and password.

    Returns:
        LoginResponse: access_token and token_type
    """
    # In this demo, any credentials are accepted. We map to a mock user.
    user_id = data.username.strip() or "demo"
    token = _issue_token_for_user(user_id)
    return LoginResponse(access_token=token, token_type="bearer")


@app.post(
    "/auth/logout",
    tags=["Auth"],
    summary="Logout",
    description="Invalidate the current bearer token.",
    response_model=LogoutResponse,
)
# PUBLIC_INTERFACE
def logout(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """
    Logout by invalidating the provided token.

    Returns:
        LogoutResponse with a simple message.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        # Idempotent logout - if no token, still respond with 200 for simplicity.
        return LogoutResponse(detail="Logged out")
    _revoke_token(credentials.credentials)
    return LogoutResponse(detail="Logged out")


# Notes endpoints
@app.get(
    "/notes",
    tags=["Notes"],
    summary="List notes",
    description="List all notes for the current user.",
    response_model=List[Note],
)
# PUBLIC_INTERFACE
def list_notes(user_id: str = Depends(get_current_user)):
    """
    List all notes belonging to the authenticated user.
    """
    with _db_lock:
        conn = _get_conn()
        try:
            cur = conn.execute("SELECT * FROM notes WHERE owner=? ORDER BY datetime(created_at) DESC", (user_id,))
            rows = cur.fetchall()
            return [_row_to_note(r) for r in rows]
        finally:
            conn.close()


@app.post(
    "/notes",
    tags=["Notes"],
    summary="Create note",
    description="Create a new note for the current user.",
    response_model=Note,
    status_code=status.HTTP_201_CREATED,
)
# PUBLIC_INTERFACE
def create_note(payload: NoteCreate, user_id: str = Depends(get_current_user)):
    """
    Create a new note for the authenticated user.
    """
    note_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    with _db_lock:
        conn = _get_conn()
        try:
            conn.execute(
                "INSERT INTO notes (id, title, content, created_at, updated_at, owner) VALUES (?,?,?,?,?,?)",
                (note_id, payload.title, payload.content, now, now, user_id),
            )
            conn.commit()
        finally:
            conn.close()
    return Note(id=note_id, title=payload.title, content=payload.content, created_at=datetime.fromisoformat(now),
                updated_at=datetime.fromisoformat(now), owner=user_id)


@app.get(
    "/notes/{note_id}",
    tags=["Notes"],
    summary="Get note",
    description="Retrieve a single note by id for the current user.",
    response_model=Note,
)
# PUBLIC_INTERFACE
def get_note(
    note_id: str = Path(..., description="UUID of the note"),
    user_id: str = Depends(get_current_user),
):
    """
    Get a note by id for the authenticated user.
    """
    note = _fetch_note_for_owner(note_id, user_id)
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    return note


@app.put(
    "/notes/{note_id}",
    tags=["Notes"],
    summary="Update note",
    description="Update an existing note's title and/or content.",
    response_model=Note,
)
# PUBLIC_INTERFACE
def update_note(
    payload: NoteUpdate,
    note_id: str = Path(..., description="UUID of the note"),
    user_id: str = Depends(get_current_user),
):
    """
    Update a note by id for the authenticated user.
    """
    existing = _fetch_note_for_owner(note_id, user_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    new_title = payload.title if payload.title is not None else existing.title
    new_content = payload.content if payload.content is not None else existing.content
    now = datetime.utcnow().isoformat()

    with _db_lock:
        conn = _get_conn()
        try:
            conn.execute(
                "UPDATE notes SET title=?, content=?, updated_at=? WHERE id=? AND owner=?",
                (new_title, new_content, now, note_id, user_id),
            )
            conn.commit()
        finally:
            conn.close()

    return Note(
        id=existing.id,
        title=new_title,
        content=new_content,
        created_at=existing.created_at,
        updated_at=datetime.fromisoformat(now),
        owner=user_id,
    )


@app.delete(
    "/notes/{note_id}",
    tags=["Notes"],
    summary="Delete note",
    description="Delete a note by id.",
    status_code=status.HTTP_204_NO_CONTENT,
)
# PUBLIC_INTERFACE
def delete_note(
    note_id: str = Path(..., description="UUID of the note"),
    user_id: str = Depends(get_current_user),
):
    """
    Delete a note by id for the authenticated user.
    """
    existing = _fetch_note_for_owner(note_id, user_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    with _db_lock:
        conn = _get_conn()
        try:
            conn.execute("DELETE FROM notes WHERE id=? AND owner=?", (note_id, user_id))
            conn.commit()
        finally:
            conn.close()
    # 204 No Content
    return
