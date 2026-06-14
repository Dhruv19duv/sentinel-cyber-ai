FROM python:3.12-slim

LABEL org.opencontainers.image.title="Sentinel Cyber AI"
LABEL org.opencontainers.image.description="Enterprise Multi-Agent Cybersecurity Platform"
LABEL org.opencontainers.image.version="2.0.0"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install additional ML dependencies
RUN pip install --no-cache-dir \
    "unsloth[cu126] @ git+https://github.com/unslothai/unsloth.git" \
    fastapi \
    uvicorn[standard] \
    pydantic \
    python-multipart \
    pyyaml \
    psutil

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p data/processed outputs/models outputs/reports outputs/benchmarks

# Expose API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default: start API server
CMD ["python", "-m", "src.main", "serve"]
