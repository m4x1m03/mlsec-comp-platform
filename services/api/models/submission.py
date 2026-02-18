from sqlalchemy import Column, String, Boolean, TIMESTAMP, ForeignKey, Table, text # type: ignore
from sqlalchemy.dialects.postgresql import UUID # type: ignore
import uuid

from core.database import Base

# Register users table in metadata so submissions.user_id foreign key can resolve
# even when only submission models are imported in the API process/tests.
users_table = Table(
    "users",
    Base.metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("username", String, nullable=False, unique=True),
    Column("email", String, nullable=False, unique=True),
    Column("is_admin", Boolean, nullable=False, server_default=text("FALSE")),
    Column(
        "created_at",
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    ),
    Column("disabled_at", TIMESTAMP(timezone=True)),
    extend_existing=True,
)


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
