from sqlalchemy import Column, DateTime, Enum, Integer, String
from src.core.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    hashed_password = Column(String, nullable=False)


class UserInvited(Base):
    __tablename__ = "users_invited"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    invitation_link = Column(String, nullable=False)
    invitation_expires = Column(DateTime, nullable=False)
