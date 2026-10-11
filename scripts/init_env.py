"""Generate local secrets without displaying or overwriting existing configuration."""

import hashlib
import json
import secrets
from pathlib import Path

path = Path(".env")
if path.exists():
    raise SystemExit(".env already exists; preserved")
password = secrets.token_urlsafe(32)
key = secrets.token_urlsafe(32)
record = json.dumps(
    [{"hash": hashlib.sha256(key.encode()).hexdigest(), "role": "admin", "actor": "local-owner"}],
    separators=(",", ":"),
)
content = f"POSTGRES_PASSWORD={password}\nDATABASE_URL=postgresql+psycopg://soc:{password}@127.0.0.1:5432/soc\nAPI_KEY_RECORDS='{record}'\nLOCAL_API_KEY={key}\nVERIFY_API_KEY={secrets.token_urlsafe(32)}\nLLM_BACKEND=fake\nALLOW_EXTERNAL_LLM=no\n"
path.write_text(content)
path.chmod(0o600)
print("Created private .env. Read LOCAL_API_KEY locally for dashboard login; never commit it.")
