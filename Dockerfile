# Multi-stage Dockerfile for SentinelX Web Security Auditor
FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Expose SentinelX Web Interface port
EXPOSE 5000

ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=5000
ENV PYTHONUNBUFFERED=1

CMD ["python", "app.py"]
