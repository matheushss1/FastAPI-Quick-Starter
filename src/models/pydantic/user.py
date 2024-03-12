from datetime import datetime, timedelta
from typing import Optional

from pydantic import BaseModel


class User(BaseModel):
    name: str
    email: str
    scopes: List[str] = ["users:self"]


class UserInvited(User):
    invitation_link: Optional[str] = None
    invitation_expires: datetime = datetime.now() + timedelta(days=1)


class UserCredentials(BaseModel):
    email: str
    password: str


class UserCreation(BaseModel):
    name: str
    email: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class UserInDB(User):
    id: int
    hashed_password: str
