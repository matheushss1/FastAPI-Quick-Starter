from sqlalchemy import Column, Enum, Integer, String
from src.core.database import Base

MODULES = ["users"]
MODES = ["self", "r", "rw", "all"]


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=False)
    module = Column(Enum(*MODULES, name="modules"), nullable=False)
    mode = Column(Enum(*MODES, name="modes"), nullable=False)
