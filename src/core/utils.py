from typing import Dict, List

from fastapi import HTTPException, status
from fastapi.security import SecurityScopes
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from src.models.orm.user import User as UserORM
from src.models.pydantic.user import User as UserPydantic

