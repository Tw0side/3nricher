# 3nricher — IOC enrichment pipeline

# ---- Stage 1: build dependencies ----
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# ---- Stage 2: runtime ----
FROM python:3.11-slim

# Build args MUST be declared AFTER FROM, before use
ARG UID=1000
ARG GID=1000

# Create non-root user with the specified UID/GID
RUN groupadd -g "${GID}" appuser \
 && useradd -m -u "${UID}" -g "${GID}" appuser

WORKDIR /app

COPY --from=builder /root/.local /home/appuser/.local
COPY --chown="${UID}:${GID}" . .

ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

RUN mkdir -p /app/cache /app/data \
 && chown -R "${UID}:${GID}" /app/cache /app/data

USER appuser

ENTRYPOINT ["python", "3nricher.py"]
CMD ["--help"]
