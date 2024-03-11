from typing import Annotated, Generator

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from src.config.settings import Settings
from src.core.database import SessionLocal
from src.models.orm.user import User as SQLAlchemyUser
from src.models.pydantic.user import TokenData, User


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_settings() -> Settings:
    return Settings()


OAUTH2_SCOPES = {
    "users:self": "Read/Update self",
    "users:r": "Read information about all users",
    "users:rw": "Read and write information about all users",
    "users:all": "All operations allowed for users",
}

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/user/token", scopes=OAUTH2_SCOPES
)


def get_current_user(
    security_scopes: SecurityScopes,
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db),
) -> User:
    """
    Decodes the JWT and checks for the authenticated
    user that is performing the request. Also checks the permission scopes.
    """
    SETTINGS = get_settings()
    SECRET_KEY = SETTINGS.SECRET_KEY
    ALGORITHM = SETTINGS.ALGORITHM

    if security_scopes.scopes:
        authenticate_value = f"Bearer scopes={security_scopes.scope_str}"
    else:
        authenticate_value = "Bearer"

    CREDENTIALS_EXCEPTION = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise CREDENTIALS_EXCEPTION
    except JWTError:
        raise credentials_exception
    user = (
        db.query(SQLAlchemyUser)
        .filter(SQLAlchemyUser.email == token_data.email)
        .one()
    )
    if user:
        return User(name=user.name, last_name=user.last_name, email=user.email)
    raise credentials_exception
