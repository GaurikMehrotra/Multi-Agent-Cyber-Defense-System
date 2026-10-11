#!/usr/bin/env bash
# Start retained services; preserve owner configuration and any active stop flag.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export DOCKER_CONFIG=/workspace/.docker
export LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)"
mkdir -p runtime
# Networks remain internal at runtime; never use host networking for Nmap.
docker compose --profile core up -d --wait --wait-timeout 60 postgres
docker compose --profile agents run --rm --no-deps api alembic upgrade head
docker compose --profile agents up -d --no-build --wait --wait-timeout 60 api worker dashboard
docker compose exec -T api python - <<'PY'
import json
import os
import httpx
with httpx.Client(base_url="http://127.0.0.1:8000", trust_env=False, timeout=5,
        headers={"X-API-Key": os.environ["LOCAL_API_KEY"]}) as client:
    health = client.get("/health")
    health.raise_for_status()
    events = client.get("/events?limit=1")
    events.raise_for_status()
    print(json.dumps({"health": health.json(), "authenticated_query_verified": True}))
PY
