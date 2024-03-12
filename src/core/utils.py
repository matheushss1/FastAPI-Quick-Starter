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


def check_if_user_has_permissions(
    user_scopes: List[str], requested_scopes: List[str]
) -> bool:
    for scope in requested_scopes:
        if scope not in user_scopes:
            return False
    return True


def get_credentials_exceptions(
    security_scopes: SecurityScopes, forbidden: bool = False
) -> HTTPException:
    if security_scopes.scopes:
        authenticate_value = f"Bearer scopes={security_scopes.scope_str}"
    else:
        authenticate_value = "Bearer"

    if forbidden:
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
            headers={"WWW-Authenticate": authenticate_value},
        )

    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )

