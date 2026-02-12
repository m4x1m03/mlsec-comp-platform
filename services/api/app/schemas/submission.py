from pydantic import BaseModel # type: ignore
from typing import Optional


class DefenseSubmitRequest(BaseModel):
    version: str
    display_name: Optional[str]
    source_type: str
    docker_image: Optional[str]
    git_repo: Optional[str]
    object_key: str
    sha256: Optional[str]
