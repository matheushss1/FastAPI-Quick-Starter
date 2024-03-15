from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_mail import FastMail, MessageSchema, MessageType
from sqlalchemy.orm import Session
from src.core.dependencies import get_db
from src.core.email import get_fast_mail
from src.core.security import get_current_user
from src.core.utils import get_user_scopes
from src.managers.users import UserManager
from src.models.pydantic.user import (
    Token,
    User,
    UserCreation,
    UserCredentials,
    UserInvited,
)

router = APIRouter(prefix="/user")


@router.post(
    "/signup",
    status_code=status.HTTP_201_CREATED,
    response_model=User,
    dependencies=[Security(get_current_user, scopes=["users:rw"])],
)
def create_user(
    user_creation: UserCreation, db: Session = Depends(get_db)
) -> User:
    return UserManager(db).create_user(user_creation)


@router.post(
    "/invite",
    status_code=status.HTTP_200_OK,
    response_model=UserInvited,
    dependencies=[Security(get_current_user, scopes=["users:rw"])],
)
async def invite_user(
    user: UserInvited,
    fast_mail: FastMail = Depends(get_fast_mail),
    db: Session = Depends(get_db),
) -> UserInvited:
    user_invited = UserManager(db).create_invited_user(user)

    message = MessageSchema(
        subject="Invite to use software",
        recipients=[user_invited.model_dump().get("email")],
        template_body=user_invited.model_dump(),
        subtype=MessageType.html,
    )

    await fast_mail.send_message(
        message, template_name="invite_user_template.html"
    )
    return user_invited


@router.post(
    "/confirm-invitation", status_code=status.HTTP_200_OK, response_model=User
)
async def confirm_user_invitation(
    user_credentials: UserCredentials, db: Session = Depends(get_db)
) -> User:
    return UserManager(db).confirm_invitation(user_credentials)


@router.post("/token", status_code=status.HTTP_200_OK, response_model=Token)
async def login(
    user_credentials: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
) -> Token:
    user_manager = UserManager(db)
    user = user_manager.authenticate_user(
        email=user_credentials.username, password=user_credentials.password
    )
    user_scopes = get_user_scopes(roles=user.roles)
    data = {"sub": user.email, "scopes": user_scopes}
    access_token = user_manager.create_access_token(data)
    return Token(access_token=access_token, token_type="bearer")


@router.get(
    "/me",
    response_model=User,
    dependencies=[Security(get_current_user, scopes=["users:self"])],
)
async def get_logged_user(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    return UserManager(db).get_db_user_by_email(user.email)
