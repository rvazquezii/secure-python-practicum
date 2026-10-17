#!/bin/sh
# Serve the course locally. Python needs a real HTTP origin (module imports and
# the WebAssembly runtime are both blocked on file:// URLs).
#
#   ./serve.sh          -> http://localhost:8800
#   ./serve.sh 9000     -> http://localhost:9000
#
# Responses are sent no-store: browsers cache ES modules aggressively, so without
# this an edited lesson or script keeps serving the previous version.

PORT="${1:-8800}"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Secure Python  ->  http://localhost:${PORT}"
echo "serving ${DIR}  (ctrl-c to stop)"

exec python3 - "$PORT" "$DIR" <<'PY'
import functools, sys
from http.server import HTTPServer, SimpleHTTPRequestHandler

port, directory = int(sys.argv[1]), sys.argv[2]


class NoCacheHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store, must-revalidate")
        super().end_headers()


handler = functools.partial(NoCacheHandler, directory=directory)
HTTPServer(("127.0.0.1", port), handler).serve_forever()
PY
