from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.core.database import Base, build_database_uri
from src.managers.users import UserManager
from src.models.orm.roles import MODES, MODULES, Role
from src.models.orm.user import User

INITIAL_PASSWORD = "password"

engine = create_engine(build_database_uri())
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)


def create_initial_user():
    db = SessionLocal()
    if (
        db.query(User).count() == 0
        and db.query(Role)
        .filter(Role.module == "users" and Role.mode == "all")
        .count()
        == 0
    ):
        print("Couldn't find any Role and User. Creating the first ones.")
        roles = []
        for module in MODULES:
            for mode in MODES:
                modes_roles_dict = {
                    "all": "admin",
                    "rw": "manager",
                    "r": "user",
                    "self": "member",
                }
                roles_description_dict = {
                    "self": f"Read/Update own {module}",
                    "r": f"Read information about all {module}",
                    "rw": f"Read and write information about all {module}",
                    "all": f"All operations allowed for {module}",
                }
                role = Role(
                    name=modes_roles_dict.get(mode),
                    description=roles_description_dict.get(mode),
                    module=module,
                    mode=mode,
                )
                roles.append(role)
                db.add(role)
        password_hash = UserManager(db).get_password_hash(INITIAL_PASSWORD)
        admin_user = User(
            name="Admin",
            email="admin@admin.com",
            hashed_password=password_hash,
        )
        for role in roles:
            admin_user.roles.append(role)
        db.add(admin_user)
        db.commit()
        db.close()
        print("Created default user. Don't forget to change its credentials.")
    else:
        print("Users already created. Skipping...")


if __name__ == "__main__":
    create_initial_user()
