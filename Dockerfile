FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/app

WORKDIR /app

COPY pyproject.toml README.md ./
COPY ledgerhound ./ledgerhound
COPY config ./config
COPY alembic.ini ./alembic.ini

RUN pip install --no-cache-dir . \
    && groupadd --gid 1000 app \
    && useradd --uid 1000 --gid app --create-home --home-dir /home/app app \
    && chown -R app:app /app

USER app

ENTRYPOINT []
CMD ["lh", "--help"]
