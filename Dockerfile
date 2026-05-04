# ============================================================
# OWASP WSTG Security Scanner — Dockerfile
# ============================================================
# Build:  docker compose build scanner
# Run:    docker compose run --rm scanner --target http://TARGET
#
# Reports → scanner/reports/   Evidence → scanner/evidence/
# ============================================================

FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

# ── Labels ────────────────────────────────────────────────────────────
LABEL description="OWASP WSTG Python Security Scanner" \
      org.opencontainers.image.source="https://github.com/your-repo/wstg-scanner"

# ── Environment ───────────────────────────────────────────────────────
# The Playwright base image pre-installs Chromium at /ms-playwright and
# sets PLAYWRIGHT_BROWSERS_PATH accordingly — no browser install needed.
# PYTHONUNBUFFERED: ensure log output is flushed immediately to stdout
# so docker logs show real-time scan progress.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ── System dependencies ───────────────────────────────────────────────
# nikto is not in the standard Debian/Ubuntu repos — clone it from
# GitHub and symlink the Perl script onto PATH. perl and
# libnet-ssleay-perl are its only runtime dependencies.
# git is purged after the clone to keep the image lean.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        wget \
        git \
        perl \
        libnet-ssleay-perl \
        libjson-perl \
        libxml-writer-perl \
        libnet-http-perl \
    && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && apt-get purge -y --auto-remove git \
    && rm -rf /var/lib/apt/lists/*

# ── Make Playwright browsers accessible to non-root user ──────────────
# The base image installs Chromium as root. chmod allows the non-root
# scanner user created below to execute the browser binary.
RUN chmod -R o+rx /ms-playwright

# ── Working directory ─────────────────────────────────────────────────
WORKDIR /scanner

# ── Python dependencies ───────────────────────────────────────────────
# Copy requirements before source so Docker caches this layer separately.
# Source changes will not invalidate the pip install layer.
# sqlmap is installed via pip — it is not in the standard Debian repos.
COPY scanner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir sqlmap

# ── Scanner source ────────────────────────────────────────────────────
COPY scanner/ .

# ── Non-root user ─────────────────────────────────────────────────────
# Running as a non-root user limits impact if the scanner processes
# malicious payloads returned by the target application.
RUN useradd -m -u 1001 scanner \
    && chown -R scanner:scanner /scanner

USER scanner

# ── Entry point ───────────────────────────────────────────────────────
# ENTRYPOINT makes the container behave like a binary.
# CMD provides the default argument — shows help when run with no args.
# Any arguments passed to `docker compose run` override CMD entirely.
ENTRYPOINT ["python3", "main.py"]
CMD ["--help"]
