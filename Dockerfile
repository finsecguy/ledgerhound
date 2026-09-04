FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY ledgerhound ./ledgerhound
COPY config ./config
COPY alembic.ini ./alembic.ini

RUN pip install --no-cache-dir .

ENTRYPOINT []
CMD ["lh", "--help"]
