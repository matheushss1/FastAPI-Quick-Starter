from typing import Generator

from fastapi.testclient import TestClient
from pytest import fixture
from sqlalchemy.orm import Session

from src.managers.users import UserManager
from src.models.orm.user import User

