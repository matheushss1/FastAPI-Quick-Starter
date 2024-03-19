from datetime import datetime, timedelta

from pydantic import BaseModel


class PasswordChangeRequest(BaseModel):
    link: str
    expiration: datetime = datetime.now() + timedelta(hours=1)
    user_id: int


class EmailEncoded(BaseModel):
    email: str
