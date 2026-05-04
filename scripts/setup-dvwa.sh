#!/bin/sh
# setup-dvwa.sh — Initialise DVWA's database and set security level to Low.
#
# Runs once after the DVWA container is healthy (via docker-compose dvwa-setup).
# Uses curl to POST to setup.php (creates the DB) and security.php (sets level).
# No manual browser interaction required.

DVWA_URL="${DVWA_URL:-http://dvwa}"
MAX_TRIES=20
SLEEP_SEC=5

echo "[setup-dvwa] Target: $DVWA_URL"

# ── 1. Wait until DVWA's login page is reachable ─────────────────────────────
echo "[setup-dvwa] Waiting for DVWA to be ready..."
i=0
until curl -sf "$DVWA_URL/login.php" -o /dev/null; do
    i=$((i + 1))
    if [ "$i" -ge "$MAX_TRIES" ]; then
        echo "[setup-dvwa] ERROR: DVWA did not become ready after $((MAX_TRIES * SLEEP_SEC))s"
        exit 1
    fi
    echo "[setup-dvwa] Not ready yet — retrying in ${SLEEP_SEC}s ($i/$MAX_TRIES)"
    sleep "$SLEEP_SEC"
done
echo "[setup-dvwa] DVWA is reachable."

# ── 2. Initialise the database via setup.php ─────────────────────────────────
# Must GET first to establish a PHP session, then POST with that cookie.
echo "[setup-dvwa] Initialising database..."
curl -sf \
    --cookie-jar /tmp/dvwa-setup-cookies.txt \
    "$DVWA_URL/setup.php" -o /dev/null

curl -sf \
    --cookie      /tmp/dvwa-setup-cookies.txt \
    --cookie-jar  /tmp/dvwa-setup-cookies.txt \
    --data "create_db=Create+%2F+Reset+Database" \
    "$DVWA_URL/setup.php" -o /tmp/setup-out.txt || true

echo "[setup-dvwa] Database initialisation request sent."

# Give PHP a moment to finish writing the schema.
sleep 3

# ── 3. Log in to obtain a session cookie ─────────────────────────────────────
# DVWA's login form includes a CSRF token (user_token) as a hidden field.
# We must fetch the login page first (to get PHPSESSID + the token), then
# replay both in the POST. DVWA uses single-quoted HTML attributes, e.g.:
#   <input type='hidden' name='user_token' value='TOKEN' />
echo "[setup-dvwa] Fetching login page for CSRF token..."
curl -sf \
    --cookie-jar /tmp/dvwa-cookies.txt \
    "$DVWA_URL/login.php" -o /tmp/login-page.html

# Extract user_token — handle both single-quoted (DVWA default) and double-quoted HTML.
USER_TOKEN=$(grep -i "user_token" /tmp/login-page.html | \
    grep -oE "value='[^']+'" | sed "s/value='//;s/'//" | head -1)

if [ -z "$USER_TOKEN" ]; then
    # Fallback: double-quoted attributes
    USER_TOKEN=$(grep -i "user_token" /tmp/login-page.html | \
        grep -oE 'value="[^"]+"' | sed 's/value="//;s/"//' | head -1)
fi

if [ -n "$USER_TOKEN" ]; then
    echo "[setup-dvwa] CSRF token found. Logging in..."
else
    echo "[setup-dvwa] No CSRF token found — attempting login without it."
fi

# POST credentials. Use --write-out to capture the final URL after redirects
# so we can verify login success without parsing the HTML body (which always
# contains links to login.php, causing false-positive failure detection).
FINAL_URL=$(curl -sf \
    --cookie      /tmp/dvwa-cookies.txt \
    --cookie-jar  /tmp/dvwa-cookies.txt \
    --data        "username=admin&password=password&Login=Login&user_token=${USER_TOKEN}" \
    --location \
    --write-out   "%{url_effective}" \
    "$DVWA_URL/login.php" -o /tmp/login-out.html)

echo "[setup-dvwa] Login redirected to: $FINAL_URL"
if echo "$FINAL_URL" | grep -qi "login"; then
    echo "[setup-dvwa] WARNING: Login appears to have failed (still on login page)."
    echo "[setup-dvwa]          Check credentials or run setup.php manually in your browser."
else
    echo "[setup-dvwa] Login successful."
fi

# ── 4. Set security level to Low ─────────────────────────────────────────────
echo "[setup-dvwa] Setting security level to Low..."
curl -sf \
    --cookie      /tmp/dvwa-cookies.txt \
    --cookie-jar  /tmp/dvwa-cookies.txt \
    --data        "security=low&seclev_submit=Submit" \
    "$DVWA_URL/security.php" -o /dev/null

echo "[setup-dvwa] Security level set to Low."
echo "[setup-dvwa] Setup complete. DVWA is ready to scan."
