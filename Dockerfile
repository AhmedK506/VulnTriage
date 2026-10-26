# ─────────────────────────────────────────────────────────────────────────────
# VulnTriage — single-image build for Kali / any Docker host.
#
# Stage 1 builds the React/Vite SPA into static files.
# Stage 2 runs the Flask backend (gunicorn) and serves those static files
# same-origin, so the whole app is reachable on one port.
#
# Python is pinned to 3.12 (not the 3.14 used for local dev) because the pinned
# numpy/scikit-learn/pandas versions ship prebuilt wheels for 3.12 — the image
# builds without a compiler toolchain. The app code uses no 3.14-only features.
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: build the frontend ──────────────────────────────────────────────
FROM node:20-bookworm-slim AS frontend
WORKDIR /build

# Install deps first for better layer caching.
COPY frontend/package*.json ./
RUN npm install --no-audit --no-fund

COPY frontend/ ./
RUN npm run build          # outputs to /build/dist


# ── Stage 2: backend runtime ─────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/backend \
    FLASK_ENV=production \
    FRONTEND_DIST=/app/frontend/dist

WORKDIR /app/backend

# Python deps (all pinned versions have manylinux wheels for cp312).
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Application code, the trained ML model, and the compiled SPA.
COPY backend/ /app/backend/
COPY ml_data/models/ /app/ml_data/models/
COPY --from=frontend /build/dist/ /app/frontend/dist/

# Entrypoint (strip any CRLF line endings introduced by a Windows checkout).
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN sed -i 's/\r$//' /app/docker-entrypoint.sh \
 && chmod +x /app/docker-entrypoint.sh

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://localhost:5000/api/health'); sys.exit(0)" || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "3", "--timeout", "120", "wsgi:app"]
