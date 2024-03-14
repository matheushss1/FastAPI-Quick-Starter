from contextlib import closing
from typing import Annotated

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from sqlalchemy.orm import Session
from src.core.dependencies import get_db, get_settings
from src.core.utils import (
    check_if_user_has_permissions,
    get_all_roles,
    get_credentials_exceptions,
    get_email_by_decoded_jwt,
    get_user_by_email,
    get_user_scopes,
    parse_scopes,
)
from src.models.pydantic.user import User

