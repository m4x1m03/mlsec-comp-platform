FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1 \
	PYTHONOPTIMIZE=2
# Optimize=2 can be removed later if it breaks everything

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

# Create a non-root user
RUN useradd --create-home --uid 10001 appuser
RUN mkdir -p /app/cache && chown -R appuser:appuser /app

USER appuser

CMD ["sh", "-c", "celery -A worker.celery_app:celery_app worker --loglevel=INFO --concurrency=${CELERY_CONCURRENCY:-1}"]

