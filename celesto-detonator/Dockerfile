FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements-api.txt .
RUN pip install --no-cache-dir -r requirements-api.txt
COPY src ./src
ENV PYTHONPATH=/app/src
EXPOSE 8080
# Control plane only. Celesto guests are created by the CLI/SDK, never inside this container.
CMD ["sh", "-c", "uvicorn detonator.api:app --host 0.0.0.0 --port ${API_PORT:-8080}"]
