FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# New source file? Check this COPY in the same commit. A module that exists in
# the repo but not in the image is a container that crash-loops on ImportError.
COPY mcp_gateway/ ./mcp_gateway/

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Exits non-zero on a configuration error rather than serving half-configured.
CMD ["python", "-m", "mcp_gateway"]
