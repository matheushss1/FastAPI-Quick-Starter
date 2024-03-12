from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.core.database import Base, build_database_uri
from src.managers.users import UserManager
from src.models.orm.user import User

INITIAL_PASSWORD = "password"

engine = create_engine(build_database_uri())
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)


def create_initial_user():
    db = SessionLocal()
    if db.query(User).count() == 0:
        password_hash = UserManager(db).get_password_hash(INITIAL_PASSWORD)
        admin_user = User(
            name="Admin",
            email="admin@admin.com",
            hashed_password=password_hash,
            role="admin",
        )
        db.add(admin_user)
        db.commit()
        db.close()
        print("Created default user. Don't forget to change its credentials.")
    else:
        print("Users already created. Skipping...")


if __name__ == "__main__":
    create_initial_user()
