"""Esquemas Pydantic de request/response de la API publica."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


# --- Auth ---
class LoginRequest(BaseModel):
    username: str = Field(..., examples=["team_03"])
    password: str = Field(..., examples=["s3cr3t-pass"])


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    team_id: str
    display_name: str


class MeResponse(BaseModel):
    team_id: str
    display_name: str


# --- Challenges ---
class ChallengeOut(BaseModel):
    id: str
    category: str
    name: str
    difficulty: str
    points: int
    description: str
    connection_info: str
    solved: bool
    instance_status: str = "stopped"


class SubmitRequest(BaseModel):
    flag: str = Field(..., examples=["HL4{0123456789abcdef0123}"])


class SubmitResponse(BaseModel):
    correct: bool
    already_solved: bool = False
    points_awarded: int = 0
    message: str


# --- Instances ---
InstanceStatus = Literal["stopped", "starting", "running", "error"]


class InstanceOut(BaseModel):
    challenge_id: str
    status: InstanceStatus
    message: str = ""


# --- Scoreboard ---
class ScoreboardEntry(BaseModel):
    rank: int
    team_id: str
    display_name: str
    points: int
    solves: int
    last_solve: datetime | None = None


class ScoreboardResponse(BaseModel):
    entries: list[ScoreboardEntry]
