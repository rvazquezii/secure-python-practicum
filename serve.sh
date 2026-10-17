#!/bin/sh
# Serve the course locally. Python needs a real HTTP origin (module imports and
# the WebAssembly runtime are both blocked on file:// URLs).
#
#   ./serve.sh          -> http://localhost:8800
#   ./serve.sh 9000     -> http://localhost:9000

PORT="${1:-8800}"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Secure Python  ->  http://localhost:${PORT}"
echo "serving ${DIR}  (ctrl-c to stop)"
exec python3 -m http.server "$PORT" --directory "$DIR" --bind 127.0.0.1
