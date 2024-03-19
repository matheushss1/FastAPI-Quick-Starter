from typing import List, Optional

from pydantic import BaseModel


class Role(BaseModel):
    name: str
    description: str
    module: str
    mode: str


class RoleUpdating(BaseModel):
    name: Optional[str]
    description: Optional[str]
    module: Optional[str]
    mode: Optional[str]


class UserRolesPayload(BaseModel):
    email: str
    roles_ids: List[int]
