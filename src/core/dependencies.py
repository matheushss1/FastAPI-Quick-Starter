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


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/token")


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db),
) -> User:
    """
    Decodes the JWT and checks for the authenticated
    user that is performing the request.
    """
    SETTINGS = get_settings()
    SECRET_KEY = SETTINGS.SECRET_KEY
    ALGORITHM = SETTINGS.ALGORITHM
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise credentials_exception
        token_data = TokenData(email=email)
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
