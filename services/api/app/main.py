from fastapi import FastAPI # type: ignore
from .routes import submissions

app = FastAPI()

app.include_router(
    submissions.router,
    prefix="/submissions",
    tags=["submissions"]
)
