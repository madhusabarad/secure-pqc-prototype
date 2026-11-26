"""One JSON request per process. Team code owns all application behavior."""
import json
from pathlib import Path
import sys

# Ensure local imports work regardless of cwd
sys.path.insert(0, str(Path(__file__).parent.resolve()))
from team_app import dispatch

MAX_REQUEST_SIZE = 1048576  # 1 MiB cap


def main():
    try:
        raw = sys.stdin.read(MAX_REQUEST_SIZE + 1)
        if len(raw) > MAX_REQUEST_SIZE:
            raise ValueError("Request exceeds maximum allowed size.")
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise ValueError("Request must be a JSON object.")
        response = dispatch(request)
        if not isinstance(response, dict):
            raise ValueError("Response must be a JSON object.")
        encoded = json.dumps(response, allow_nan=False)
    except Exception:
        # Never print request data, key material, or exception details to stderr.
        sys.stderr.write("Request failed; inspect team application locally.\n")
        sys.stderr.flush()
        return 1
    sys.stdout.write(encoded + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
