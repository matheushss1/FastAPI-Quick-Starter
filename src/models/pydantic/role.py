from pydantic import BaseModel


class Role(BaseModel):
    name: str
    description: str
    module: str
    mode: str
