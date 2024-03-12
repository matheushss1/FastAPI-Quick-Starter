from typing import Dict, List

from fastapi import HTTPException, status
from fastapi.security import SecurityScopes
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from src.models.orm.user import User as UserORM
from src.models.pydantic.user import User as UserPydantic


def get_user_by_email(
    db: Session, email: str, credentials_exception: HTTPException
) -> UserPydantic | None:
    user_db_list = db.query(UserORM).filter(UserORM.email == email).all()
    if len(user_db_list):
        return UserPydantic(
            name=user_db_list[0].name,
            email=user_db_list[0].email,
            role=user_db_list[0].role,
        )
    raise credentials_exception

