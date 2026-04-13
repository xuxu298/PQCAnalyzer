FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY src/ src/
COPY data/ data/

# Install Python dependencies
RUN pip install --no-cache-dir .

# Create non-root user
RUN useradd --create-home appuser
USER appuser

# Default command
ENTRYPOINT ["pqc-analyzer"]
CMD ["--help"]
