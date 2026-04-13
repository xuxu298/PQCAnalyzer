FROM python:3.11-slim AS base

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY src/ src/
COPY data/ data/

# Install Python dependencies (core + web)
RUN pip install --no-cache-dir ".[web]"

# Create non-root user
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

# Default: run API server
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

# --- Web frontend build stage ---
FROM node:20-alpine AS web-build
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm ci
COPY web/ .
RUN npm run build

# --- Full image with web frontend served by nginx ---
FROM nginx:alpine AS web
COPY --from=web-build /web/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
