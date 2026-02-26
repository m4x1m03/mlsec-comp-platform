FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update && apt-get install -y sudo netcat-traditional && rm -rf /var/lib/apt/lists/*

COPY . .

# create user 1000 so we match the worker's user mapping
RUN useradd -m -u 1000 defender

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
