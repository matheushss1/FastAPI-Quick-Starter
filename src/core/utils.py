from typing import List

from fastapi import HTTPException, status
from fastapi.security import SecurityScopes
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from src.models.orm.user import Role as RoleORM
from src.models.orm.user import User as UserORM
from src.models.pydantic.role import Role as RolePydantic
from src.models.pydantic.user import User as UserPydantic


def get_user_by_email(
    db: Session, email: str, credentials_exception: HTTPException
) -> UserPydantic | None:
    user_db_list = db.query(UserORM).filter(UserORM.email == email).all()
    if len(user_db_list):
        user_roles = [
            RolePydantic(
                name=role.name,
                description=role.description,
                module=role.module,
                mode=role.mode,
            )
            for role in user_db_list[0].roles
        ]
        return UserPydantic(
            name=user_db_list[0].name,
            email=user_db_list[0].email,
            roles=user_roles,
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


def get_user_scopes(roles: List[RolePydantic]) -> List[str]:
    return list(parse_scopes(roles).keys())


def get_email_by_decoded_jwt(
    token: str,
    secret_key: str,
    algorithm: str,
    credentials_exception: HTTPException,
) -> str:
    email = None
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        email = payload.get("sub")
        if not email:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    finally:
        return email


def generate_role_description(module: str, mode: str) -> str:
    roles_description_dict = {
        "self": f"Read/Update own {module}",
        "r": f"Read information about all {module}",
        "rw": f"Read/Update information about all {module}",
        "all": f"All operations allowed for {module}",
    }
    return roles_description_dict.get(mode)


def generate_role_name(mode: str) -> str:
    modes_roles_dict = {
        "all": "admin",
        "rw": "manager",
        "r": "user",
        "self": "member",
    }
    return modes_roles_dict.get(mode)


def get_all_roles(db: Session) -> List[RolePydantic]:
    roles = db.query(RoleORM).all()
    return [
        RolePydantic(
            name=role.name,
            description=role.description,
            module=role.module,
            mode=role.mode,
        )
        for role in roles
    ]


def parse_scopes(roles: List[RolePydantic]) -> dict[str, str]:
    scopes = {}
    for role in roles:
        scope_key = f"{role.module}:{role.mode}"
        scope_value = role.description
        scopes[scope_key] = scope_value
    return scopes
