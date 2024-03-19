from typing import Annotated

from fastapi import APIRouter, Depends, Security, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_mail import FastMail, MessageSchema, MessageType
from sqlalchemy.orm import Session
from src.core.dependencies import get_db
from src.core.email import get_fast_mail
from src.core.security import get_current_user
from src.core.utils import get_user_scopes
from src.managers.users import UserManager
from src.models.pydantic.password_request import EmailEncoded
from src.models.pydantic.user import (
    Token,
    User,
    UserCreation,
    UserCredentials,
    UserInvited,
    UserUpdating,
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


@router.put("/me", response_model=User, status_code=status.HTTP_200_OK)
async def update_logged_user(
    updates: UserUpdating,
    db: Session = Depends(get_db),
    user: User = Security(get_current_user, scopes=["users:self"]),
) -> User:
    return UserManager(db).update_user(updates, user)


@router.delete(
    "/{id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Security(get_current_user, scopes=["users:all"])],
)
async def delete_user(id: int, db: Session = Depends(get_db)) -> None:
    return UserManager(db).delete_user(id)


@router.put(
    "/me/forgot-password",
    status_code=status.HTTP_200_OK,
)
async def request_password_change(
    email_encoded: EmailEncoded,
    db: Session = Depends(get_db),
    fast_mail: FastMail = Depends(get_fast_mail),
) -> dict:
    password_change_request_and_user = UserManager(
        db
    ).create_password_change_request(email_encoded.email)
    body_variables = {
        **password_change_request_and_user.get("user").model_dump(),
        "link": password_change_request_and_user.get(
            "password_change_request"
        ).link,
        # Adjust timezone as needed!
        "expiration": password_change_request_and_user.get(
            "password_change_request"
        ).expiration.strftime("%d/%m/%Y %H:%M:%S%z"),
    }
    message = MessageSchema(
        subject="Password Change Request",
        recipients=[
            password_change_request_and_user.get("user")
            .model_dump()
            .get("email")
        ],
        template_body=body_variables,
        subtype=MessageType.html,
    )

    await fast_mail.send_message(
        message, template_name="password_change_request_template.html"
    )
    return {"detail": "Success! Link to change password sent to e-mail."}
