from base64 import b64decode, b64encode
from binascii import Error as binascii_error
from datetime import datetime, timedelta, timezone
from typing import Literal, Union

from bcrypt import checkpw, gensalt, hashpw
from fastapi import HTTPException
from jose import jwt
from sqlalchemy import delete, update
from sqlalchemy.orm import Session
from src.core.dependencies import get_settings
from src.managers.utils import (
    get_db_list_of_objects_by_list_of_ids,
    get_db_single_object_by_email,
    get_db_single_object_by_id,
)
from src.models.orm.user import PasswordChangeRequest as PasswordRequestORM
from src.models.orm.user import Role as RoleORM
from src.models.orm.user import User as UserOrm
from src.models.orm.user import UserInvited as UserInvitedORM
from src.models.pydantic.password_request import (
    PasswordChangeRequest as PasswordRequestPydantic,
)
from src.models.pydantic.role import Role as RolePydantic
from src.models.pydantic.user import User as UserPydantic
from src.models.pydantic.user import (
    UserCreation,
    UserCredentials,
    UserInvited,
    UserUpdating,
)

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
        _ = get_db_single_object_by_email(
            db=self.db,
            model=UserInvitedORM,
            email=user_invited_creation.email,
            exception=HTTPException(400, "E-mail already registered"),
            expect_none=True,
        )
        invitation_link = self.create_user_link(
            user_invited_creation.email,
        )
        user_invited_roles = get_db_list_of_objects_by_list_of_ids(
            db=self.db,
            model=RoleORM,
            list_of_ids=user_invited_creation.roles_ids,
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
        _ = get_db_single_object_by_email(
            db=self.db,
            model=UserOrm,
            email=user_creation.email,
            exception=HTTPException(400, "E-mail already registered"),
            expect_none=True,
        )
        user_roles = get_db_list_of_objects_by_list_of_ids(
            db=self.db, model=RoleORM, list_of_ids=user_creation.roles_ids
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
        user = get_db_single_object_by_email(
            db=self.db,
            model=UserOrm,
            email=email,
            exception=HTTPException(404, "User not found"),
        )
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

    def update_user(
        self, updating: UserUpdating, user: UserPydantic
    ) -> UserPydantic:
        user_to_be_updated = get_db_single_object_by_email(
            db=self.db,
            model=UserOrm,
            email=user.email,
            exception=HTTPException(500, "Something is really wrong"),
        )
        statement = (
            update(UserOrm)
            .where(UserOrm.id == user_to_be_updated.id)
            .values(**updating.model_dump(exclude_unset=True))
        )
        self.db.execute(statement)
        self.db.commit()
        return self.get_db_user_by_email(user.email)

    def delete_user(self, id: int) -> None:
        _ = get_db_single_object_by_id(
            db=self.db,
            model=UserOrm,
            id=id,
            exception=HTTPException(404, "Couldn't find user."),
        )
        statement = delete(UserOrm).where(UserOrm.id == id)
        self.db.execute(statement)
        self.db.commit()
        return

    def get_db_user_invited_by_email(self, email: str) -> UserInvited:
        user_invited = get_db_single_object_by_email(
            db=self.db,
            model=UserInvitedORM,
            email=email,
            exception=HTTPException(404, "User Invited not found"),
        )
        return UserInvited(
            name=user_invited.name,
            email=user_invited.email,
            invitation_link=user_invited.invitation_link,
            invitation_expires=user_invited.invitation_expires,
            roles_ids=[role.id for role in user_invited.roles],
        )

    def create_password_change_request(
        self, user: UserPydantic
    ) -> PasswordRequestPydantic:
        user_db = get_db_single_object_by_email(
            db=self.db,
            model=UserOrm,
            email=user.email,
            exception=HTTPException(500, "Something is really wrong."),
        )
        if user_db.password_change_request:
            old_password_change_request = user_db.password_change_request
            if not self.deleted_expired_password_request(
                old_password_change_request
            ):
                raise HTTPException(
                    400,
                    (
                        "Password change already requested."
                        " Please check your e-mail."
                    ),
                )
        link = self.create_user_link(
            email=user.email, is_password_change_request=True
        )
        expiration = datetime.now() + timedelta(hours=1)
        password_change_request = PasswordRequestORM(
            link=link, expiration=expiration, user_id=user_db.id
        )
        self.db.add(password_change_request)
        self.db.commit()

    def decode_base64_str(self, to_be_decoded: str) -> str:
        result = None
        try:
            result = b64decode(to_be_decoded.encode()).decode()
        except binascii_error as _:
            raise HTTPException(500, "Something is really wrong!")
        return result

    def deleted_expired_password_request(
        self, password_change_request: PasswordRequestORM
    ) -> bool:
        if password_change_request.expiration < datetime.now():
            statement = delete(PasswordRequestORM).where(
                PasswordRequestORM.id == password_change_request.id
            )
            self.db.execute(statement)
            self.db.commit()
            return True
        return False

    def create_user_link(
        self, email: str, is_password_change_request: bool = False
    ) -> str:
        encoded = md5(email.encode())
        path = "invitations/" if not is_password_change_request else "request/"
        return SETTINGS.FRONTEND_URL + path + encoded.hexdigest()

    def verify_password(
        self, plain_password: str, hashed_password: str
    ) -> None:
        """
        Checks if password is correct.
        """
        password_byte_enc = plain_password.encode("utf-8")
        hashed_password = hashed_password.encode()
        if checkpw(
            password=password_byte_enc, hashed_password=hashed_password
        ):
            return
        raise HTTPException(
            400,
            "Incorrect e-mail or password",
            headers={"WWW-Authenticate": "Bearer"},
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
    ) -> UserPydantic | Literal[False]:
        """
        Checks if user and password are correct.
        """
        user = get_db_single_object_by_email(
            db=self.db,
            model=UserOrm,
            email=email,
            exception=HTTPException(
                400,
                "Incorrect e-mail or password",
                headers={"WWW-Authenticate": "Bearer"},
            ),
        )
        _ = self.verify_password(password, user.hashed_password)
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
