from datetime import datetime, timedelta
from typing import List, Optional

from pydantic import BaseModel
from src.models.pydantic.role import Role


class User(BaseModel):
    name: str
    email: str
    roles: List[Role]


class UserInvited(BaseModel):
    name: str
    email: str
    roles_ids: List[int]
    invitation_link: Optional[str] = None
    invitation_expires: datetime = datetime.now() + timedelta(days=1)


class UserCredentials(BaseModel):
    email: str
    password: str


class UserCreation(BaseModel):
    name: str
    email: str
    password: str
    roles_ids: List[int]


class Token(BaseModel):
    access_token: str
    token_type: str


class UserInDB(User):
    id: int
    hashed_password: str
