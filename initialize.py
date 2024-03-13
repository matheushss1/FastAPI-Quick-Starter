from typing import List

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from src.core.database import Base, build_database_uri
from src.managers.users import UserManager
from src.models.orm.roles import MODES, MODULES, Role
from src.models.orm.user import User

INITIAL_PASSWORD = "password"

engine = create_engine(build_database_uri())
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)


def user_and_roles_exists(db: Session) -> bool:
    if (
        db.query(User).count() == 0
        and db.query(Role)
        .filter(Role.module == "users" and Role.mode == "all")
        .count()
        == 0
    ):
        return False
    return True


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


def create_roles(db: Session) -> List[Role]:
    roles = []
    for module in MODULES:
        for mode in MODES:
            role = Role(
                name=generate_role_name(mode),
                description=generate_role_description(module, mode),
                module=module,
                mode=mode,
            )
            roles.append(role)
            db.add(role)
    return roles


def create_initial_roles_and_user():
    db = SessionLocal()
    if user_and_roles_exists(db):
        print("Users already created. Skipping...")
        return

    print("Couldn't find any Role and User. Creating the first ones.")

    password_hash = UserManager(db).get_password_hash(INITIAL_PASSWORD)
    admin_user = User(
        name="Admin",
        email="admin@admin.com",
        hashed_password=password_hash,
    )

    roles = create_roles(db)
    for role in roles:
        admin_user.roles.append(role)

    db.add(admin_user)
    db.commit()
    db.close()
    print("Created default user. Don't forget to change its credentials.")


if __name__ == "__main__":
    create_initial_roles_and_user()
