from sqlalchemy import Column, String, Boolean, TIMESTAMP, ForeignKey, text # type: ignore
from sqlalchemy.dialects.postgresql import UUID # type: ignore
import uuid

from ..core.database import Base


class Submission(Base):
    __tablename__ = "submissions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )

    submission_type = Column(String, nullable=False)

    version = Column(String, nullable=False)

    display_name = Column(String)

    status = Column(String, nullable=False, server_default="submitted")

    is_functional = Column(Boolean)

    functional_error = Column(String)

    created_at = Column(
        TIMESTAMP(timezone=True),
        server_default=text("CURRENT_TIMESTAMP")
    )

    deleted_at = Column(TIMESTAMP(timezone=True))