from datetime import datetime, timedelta, timezone
from hashlib import md5
from typing import Literal

from bcrypt import checkpw, gensalt, hashpw
from fastapi import HTTPException
from jose import jwt
from sqlalchemy import delete
from sqlalchemy.orm import Session
from src.core.dependencies import get_settings
from src.models.orm.user import Role as RoleORM
from src.models.orm.user import User as UserOrm
from src.models.orm.user import UserInvited as UserInvitedORM
from src.models.pydantic.role import Role as RolePydantic
from src.models.pydantic.user import User as UserPydantic
from src.models.pydantic.user import UserCreation, UserCredentials, UserInvited

SETTINGS = get_settings()
SECRET_KEY = SETTINGS.SECRET_KEY
ALGORITHM = SETTINGS.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = SETTINGS.ACCESS_TOKEN_EXPIRE_MINUTES


class UserManager:
    def __init__(self, db: Session):
        self.db = db

    def create_invited_user(
        self, user_invited_creation: UserInvited
    ) -> UserInvited:
        """
        Creates a user_invited
        """
        user_invited_in_db = (
            self.db.query(SQLAlchemyUserInvited)
            .filter(SQLAlchemyUserInvited.email == user_invited_creation.email)
            .all()
        )
        if len(user_invited_in_db):
            raise HTTPException(400, "E-mail already registered")
        invitation_link = self.create_invitation_link(
            user_invited_creation.email,
        )
        statement = insert(SQLAlchemyUserInvited).values(
            name=user_invited_creation.name,
            email=user_invited_creation.email,
            invitation_expires=user_invited_creation.invitation_expires,
            invitation_link=invitation_link,
        )
        self.db.execute(statement)
        self.db.commit()
        return self.get_db_user_invited_by_email(user_invited_creation.email)

    def confirm_invitation(
        self, user_credentials: UserCredentials
    ) -> PydanticUser:
        """
        Creates the user and deletes the user_invited
        """
        user_invited = self.get_db_user_invited_by_email(
            user_credentials.email
        )

        statement = delete(SQLAlchemyUserInvited).where(
            SQLAlchemyUserInvited.email == user_invited.email
        )
        self.db.execute(statement)
        self.db.commit()

        if user_invited.invitation_expires < datetime.now():
            raise HTTPException(400, "User Invitation expired")

        user_creation = UserCreation(
            name=user_invited.name,
            email=user_invited.email,
            password=user_credentials.password,
        )
        return self.create_user(user_creation)

    def create_user(self, user_creation: UserCreation) -> PydanticUser:
        """
        Creates a user directly by inputting
        the name, email, role and password.
        """
        user_in_db = (
            self.db.query(SQLAlchemyUser)
            .filter(SQLAlchemyUser.email == user_creation.email)
            .all()
        )
        if len(user_in_db):
            raise HTTPException(400, "E-mail already registered")
        statement = insert(SQLAlchemyUser).values(
            name=user_creation.name,
            email=user_creation.email,
            hashed_password=self.get_password_hash(user_creation.password),
            role="member",
        )
        self.db.execute(statement)
        self.db.commit()
        return self.get_db_user_by_email(user_creation.email)

    def get_db_user_by_email(self, email: str) -> PydanticUser:
        """
        Query the DB for the user with the given e-mail.
        """
        user = (
            self.db.query(SQLAlchemyUser)
            .filter(SQLAlchemyUser.email == email)
            .one()
        )
        if user:
            return PydanticUser(
                name=user.name,
                email=user.email,
                role=user.role,
            )
        raise HTTPException(404, "User not found")

    def get_db_user_invited_by_email(self, email: str) -> UserInvited:
        user_invited = (
            self.db.query(SQLAlchemyUserInvited)
            .filter(SQLAlchemyUserInvited.email == email)
            .one()
        )
        if user_invited:
            return UserInvited(
                name=user_invited.name,
                email=user_invited.email,
                invitation_link=user_invited.invitation_link,
                invitation_expires=user_invited.invitation_expires,
            )
        raise HTTPException(404, "User Invited not found")

    def create_invitation_link(self, email: str) -> str:
        encoded = md5(email.encode())
        return SETTINGS.FRONTEND_URL + "invitations/" + encoded.hexdigest()

    def verify_password(
        self, plain_password: str, hashed_password: str
    ) -> bool:
        """
        Checks if password is correct.
        """
        password_byte_enc = plain_password.encode("utf-8")
        hashed_password = hashed_password.encode()
        return checkpw(
            password=password_byte_enc, hashed_password=hashed_password
        )

    def get_password_hash(self, password: str) -> str:
        """
        Generates a hashed password.
        """
        pwd_bytes = password.encode("utf-8")
        salt = gensalt()
        hashed_password = hashpw(password=pwd_bytes, salt=salt)
        return hashed_password.decode()

    def authenticate_user(
        self, email: str, password: str
    ) -> PydanticUser | Literal[False]:
        """
        Checks if user and password are correct.
        """
        user_list = (
            self.db.query(SQLAlchemyUser)
            .filter(SQLAlchemyUser.email == email)
            .all()
        )
        if not len(user_list) == 1:
            return False
        user = user_list[0]
        if not self.verify_password(password, user.hashed_password):
            return False
        return PydanticUser(
            name=user.name,
            email=user.email,
            role=user.role,
        )

    def create_access_token(
        self, data: dict, expires_delta: timedelta | None = None
    ) -> str:
        """
        Creates access token for the user and sets its expiration.
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=ACCESS_TOKEN_EXPIRE_MINUTES
            )
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
