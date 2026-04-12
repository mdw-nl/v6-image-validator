#!/usr/bin/env bash
set -eu

echo "Cleaning up test images and containers..."
docker rm -f test-validator-worker 2>/dev/null || true
docker rmi harbor2.test.local/infrastructure/clean-app:v1.0 2>/dev/null || true
docker rmi harbor2.test.local/infrastructure/suspicious-app:v1.0 2>/dev/null || true
docker rmi harbor2.test.local/infrastructure/worker:v2.0 2>/dev/null || true
docker rmi registry.example.com/other/app:latest 2>/dev/null || true
echo "Done."
