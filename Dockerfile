# ============================================================
# OWASP WSTG Security Scanner — Dockerfile
# ============================================================
# Build:  docker build -t wstg-scanner .
# Run:    docker run --rm -v $(pwd)/reports:/scanner/reports \
#           wstg-scanner --target http://TARGET --output reports/scan
# ============================================================

FROM python:3.11-slim

# ── Labels ────────────────────────────────────────────────────────────
LABEL description="OWASP WSTG Python Security Scanner" \
      org.opencontainers.image.source="https://github.com/your-repo/wstg-scanner"

# ── Environment ───────────────────────────────────────────────────────
# PLAYWRIGHT_BROWSERS_PATH: install Chromium to a fixed, world-readable
# location so both the root user (build) and the non-root scanner user
# (runtime) can find the browser binary.
# PYTHONUNBUFFERED: ensure log output is flushed immediately to stdout
# so docker logs show real-time scan progress.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ── System dependencies ───────────────────────────────────────────────
# sqlmap and nikto are optional — the scanner degrades gracefully if they
# are absent. They are included here for the full Kali-style experience.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        wget \
        nikto \
        sqlmap \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ─────────────────────────────────────────────────
WORKDIR /scanner

# ── Python dependencies ───────────────────────────────────────────────
# Copy requirements before source so Docker caches this layer separately.
# Source changes will not invalidate the pip install layer.
COPY scanner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Playwright: system libraries + Chromium browser ───────────────────
# playwright install-deps  — installs the OS libraries Chromium needs
#                            (libnss3, libatk, libdrm, etc.)
# playwright install       — downloads the Chromium binary itself
# chmod                    — makes the binary readable by all users so
#                            the non-root scanner user can launch it
RUN playwright install-deps chromium \
    && playwright install chromium \
    && chmod -R o+rx /opt/ms-playwright

# ── Scanner source ────────────────────────────────────────────────────
COPY scanner/ .

# ── Non-root user ─────────────────────────────────────────────────────
# Running as a non-root user limits impact if the scanner processes
# malicious payloads returned by the target application.
RUN useradd -m -u 1000 scanner \
    && chown -R scanner:scanner /scanner

USER scanner

# ── Reports output directory ──────────────────────────────────────────
# Mount a host directory here to retrieve reports after the scan:
#   -v $(pwd)/reports:/scanner/reports
# Pass --output reports/scan to write reports into this directory.
RUN mkdir -p /scanner/reports

VOLUME ["/scanner/reports"]

# ── Entry point ───────────────────────────────────────────────────────
# ENTRYPOINT makes the container behave like a binary.
# CMD provides the default argument — shows help when run with no args.
# Any arguments passed to `docker run` override CMD entirely.
#
# Examples:
#   docker run wstg-scanner --help
#   docker run -v $(pwd)/reports:/scanner/reports wstg-scanner \
#     --target http://dvwa --output reports/scan --format both
ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
