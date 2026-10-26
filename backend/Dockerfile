FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN addgroup --system appgroup \
    && adduser --system --ingroup appgroup --home /app appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appgroup app ./app

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os, urllib.request; port = os.environ.get('PORT', '8000'); urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=3)"

CMD sh -c "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers"
