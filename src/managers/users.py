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
            self.db.query(UserInvitedORM)
            .filter(UserInvitedORM.email == user_invited_creation.email)
            .all()
        )
        if len(user_invited_in_db):
            raise HTTPException(400, "E-mail already registered")
        invitation_link = self.create_invitation_link(
            user_invited_creation.email,
        )
        user_invited_roles = (
            self.db.query(RoleORM)
            .where(RoleORM.id.in_(user_invited_creation.roles_ids))
            .all()
        )
        user_invited = UserInvitedORM(
            name=user_invited_creation.name,
            email=user_invited_creation.email,
            invitation_expires=user_invited_creation.invitation_expires,
            invitation_link=invitation_link,
        )
        for role in user_invited_roles:
            user_invited.roles.append(role)
        self.db.add(user_invited)
        self.db.commit()
        return self.get_db_user_invited_by_email(user_invited_creation.email)

    def confirm_invitation(
        self, user_credentials: UserCredentials
    ) -> UserPydantic:
        """
        Creates the user and deletes the user_invited
        """
        user_invited = self.get_db_user_invited_by_email(
            user_credentials.email
        )
        statement = delete(UserInvitedORM).where(
            UserInvitedORM.email == user_invited.email
        )
        self.db.execute(statement)
        self.db.commit()

        if user_invited.invitation_expires < datetime.now():
            raise HTTPException(400, "User Invitation expired")

        user_creation = UserCreation(
            name=user_invited.name,
            email=user_invited.email,
            password=user_credentials.password,
            roles_ids=user_invited.roles_ids,
        )
        return self.create_user(user_creation)

    def create_user(self, user_creation: UserCreation) -> UserPydantic:
        """
        Creates a user directly by inputting
        the name, email, role and password.
        """
        user_in_db = (
            self.db.query(UserOrm)
            .filter(UserOrm.email == user_creation.email)
            .all()
        )
        if len(user_in_db):
            raise HTTPException(400, "E-mail already registered")
        user_roles = (
            self.db.query(RoleORM)
            .where(RoleORM.id.in_(user_creation.roles_ids))
            .all()
        )
        user = UserOrm(
            name=user_creation.name,
            email=user_creation.email,
            hashed_password=self.get_password_hash(user_creation.password),
        )
        for role in user_roles:
            user.roles.append(role)
        self.db.add(user)
        self.db.commit()
        return self.get_db_user_by_email(user_creation.email)

    def get_db_user_by_email(self, email: str) -> UserPydantic:
        """
        Query the DB for the user with the given e-mail.
        """
        user = self.db.query(UserOrm).filter(UserOrm.email == email).one()
        if user:
            user_roles = [
                RolePydantic(
                    name=role.name,
                    description=role.description,
                    module=role.module,
                    mode=role.mode,
                )
                for role in user.roles
            ]
            return UserPydantic(
                name=user.name,
                email=user.email,
                roles=user_roles,
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
