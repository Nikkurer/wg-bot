# syntax=docker/dockerfile:1

FROM python:3.12-slim-bookworm AS base

# wg genkey / wg pubkey — client key generation stays in the bot (no root required)
RUN apt-get update \
    && apt-get install -y --no-install-recommends wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY main.py config.py client_manager.py client_ownership.py client_list.py operator_add.py wg_admin_client.py service.py bootstrap.py users.py keyboards.py states.py status_format.py ./

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin wgbot \
    && mkdir -p /var/lib/wg/clients /app/state \
    && chown -R wgbot:wgbot /app /var/lib/wg/clients /app/state

USER wgbot

CMD ["python", "main.py", "-c", "/config/config.yaml"]
