FROM python:3.11-slim

WORKDIR /app

# Copy and install dependencies
COPY pyproject.toml .
COPY security_review_agent/ security_review_agent/
COPY webhook_server.py .
RUN pip install --no-cache-dir .

# Cloud Run injects PORT env var
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 webhook_server:app
