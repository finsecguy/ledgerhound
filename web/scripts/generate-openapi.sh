#!/usr/bin/env bash
# Dumps the FastAPI app's OpenAPI schema to web/openapi.json, without
# starting a server — `app.openapi()` builds the schema in-process.
# `npm run generate:types` runs this and then openapi-typescript over
# the result; the generated src/api/schema.ts is checked in so a fresh
# `npm install && npm run build` never needs the Python backend
# importable, only when types are deliberately regenerated after an API
# change.
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON=python3
if [ -x "../.venv/bin/python" ]; then
  PYTHON="../.venv/bin/python"
fi

"$PYTHON" -c "
import json
from ledgerhound.api.main import app
print(json.dumps(app.openapi()))
" > openapi.json
echo "Wrote $(pwd)/openapi.json"
