from typing import List

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Table,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from src.core.database import Base

MODULES = ["users"]
MODES = ["self", "r", "rw", "all"]

users_roles = Table(
    "users_roles",
    Base.metadata,
    Column(
        "user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    ),
    Column(
        "role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    ),
)

users_invited_roles = Table(
    "users_invited_roles",
    Base.metadata,
    Column(
        "user_invited_id",
        ForeignKey(
            "users_invited.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    ),
    Column(
        "role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    ),
)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    hashed_password = Column(String, nullable=False)
    roles: Mapped[List["Role"]] = relationship(
        secondary=users_roles,
        back_populates="users",
    )


class UserInvited(Base):
    __tablename__ = "users_invited"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    invitation_link = Column(String, nullable=False)
    invitation_expires = Column(DateTime, nullable=False)
    roles: Mapped[List["Role"]] = relationship(
        secondary=users_invited_roles,
        back_populates="users_invited",
    )


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=False)
    module = Column(Enum(*MODULES, name="modules"), nullable=False)
    mode = Column(Enum(*MODES, name="modes"), nullable=False)
    users: Mapped[List["User"]] = relationship(
        secondary=users_roles, back_populates="roles"
    )
    users_invited: Mapped[List["UserInvited"]] = relationship(
        secondary=users_invited_roles,
        back_populates="roles",
    )
