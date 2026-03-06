FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

# Note: Running as root for Docker socket access in development
# In production, properly configure Docker group permissions
# RUN useradd --create-home --uid 10001 appuser
# USER appuser

CMD ["celery", "-A", "worker.celery_app:celery_app", "worker", "--loglevel=INFO"]

