from datetime import datetime, timedelta
from typing import Optional

from pydantic import BaseModel


class User(BaseModel):
    name: str
    last_name: str
    email: str


class UserInvited(User):
    invitation_link: Optional[str] = None
    invitation_expires: datetime = datetime.now() + timedelta(days=1)


class UserCredentials(BaseModel):
    email: str
    password: str


class UserCreation(User):
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str | None = None


class UserInDB(User):
    id: int
    hashed_password: str
