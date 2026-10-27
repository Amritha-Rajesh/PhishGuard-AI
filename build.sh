#!/usr/bin/env bash
# build.sh - Production build script for single-service Render deployment.
set -e

echo "=== [1/3] Installing Python backend dependencies ==="
pip install -r backend/requirements.txt

echo "=== [2/3] Installing React frontend dependencies and building production assets ==="
cd frontend
npm install
npm run build
cd ..

echo "=== [3/3] Build completed successfully ==="
