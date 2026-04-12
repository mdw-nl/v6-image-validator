#!/usr/bin/env bash
set -eu

echo "=== Setting up test images for check_images.sh ==="
echo ""

echo "[1/4] Building clean image (no malware files)..."
docker build -q -t harbor2.test.local/infrastructure/clean-app:v1.0 -f - . <<'DOCKERFILE'
FROM alpine:3.20
RUN echo "clean app" > /app.txt
DOCKERFILE

echo "[2/4] Building image with malware target files..."
docker build -q -t harbor2.test.local/infrastructure/suspicious-app:v1.0 -f - . <<'DOCKERFILE'
FROM alpine:3.20
RUN touch /usr/bin/checkAppend && chmod +x /usr/bin/checkAppend
RUN printf '#!/bin/sh\n' > /wrapper.sh && chmod +x /wrapper.sh
DOCKERFILE

echo "[3/4] Building worker image and running it (to test container usage tracking)..."
docker build -q -t harbor2.test.local/infrastructure/worker:v2.0 -f - . <<'DOCKERFILE'
FROM alpine:3.20
CMD ["echo", "hello from worker"]
DOCKERFILE
docker rm -f test-validator-worker 2>/dev/null || true
docker run --name test-validator-worker harbor2.test.local/infrastructure/worker:v2.0

echo "[4/4] Tagging a non-harbor image (should be ignored by the script)..."
docker pull -q alpine:3.20 >/dev/null 2>&1 || true
docker tag alpine:3.20 registry.example.com/other/app:latest

echo ""
echo "=== Test images ready ==="
echo ""
echo "Expected results from check_images.sh:"
echo "  clean-app:v1.0       -> UNKNOWN (2026+)       [never run]"
echo "  suspicious-app:v1.0  -> MALWARE FILES FOUND    [never run]"
echo "  worker:v2.0          -> UNKNOWN (2026+)       [last run $(date +%Y-%m-%d)]"
echo "  other/app:latest     -> (skipped, not harbor2)"
echo ""
echo "Note: Digest-based categories (SAFE / KNOWN AFFECTED) require images"
echo "      pulled from a real registry. Locally built images have no RepoDigests."
echo ""
echo "Run:  sudo bash check_images.sh"
