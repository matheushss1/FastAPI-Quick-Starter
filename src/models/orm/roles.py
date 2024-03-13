from sqlalchemy import Column, Enum, String
from sqlalchemy.orm import Mapped, mapped_column
from src.core.database import Base

MODULES = ["users"]
MODES = ["self", "r", "rw", "all"]


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=False)
    module = Column(Enum(*MODULES, name="modules"), nullable=False)
    mode = Column(Enum(*MODES, name="modes"), nullable=False)
