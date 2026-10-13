# Self-contained image for php7certbot-mcp. Build from the repo root:
#   podman build -t php7certbot-mcp .
# Runs as non-root. Config (.env) + the cert are injected at runtime (mounted), NEVER baked.
# OBO into certbot — the cert authenticates this app as the middle tier (client_assertion) to
# exchange the CALLER's own bearer for one audienced to certbot, so certbot sees the real user.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

# deps installed globally (as root) so any runtime UID can import them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py mcp_http_auth.py .
RUN useradd --system --uid 10001 mcp
USER mcp

EXPOSE 8785
CMD ["python", "server.py"]
