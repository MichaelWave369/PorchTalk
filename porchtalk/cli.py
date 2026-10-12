"""Read-only PorchTalk scenario evaluator."""

import argparse
from datetime import datetime
import json
from pathlib import Path
import sys

from .router import ScenarioError, evaluate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate a PorchTalk routing scenario offline. Never executes models or connects to peers.")
    parser.add_argument("scenario", type=Path, help="JSON scenario containing request, offers and grants")
    parser.add_argument("--at", help="Simulated ISO-8601 timestamp; offline testing only")
    args = parser.parse_args(argv)
    try:
        now = datetime.fromisoformat(args.at.replace("Z", "+00:00")) if args.at else None
        data = json.loads(args.scenario.read_text(encoding="utf-8"))
        output = evaluate(data, now=now)
    except (OSError, ValueError, ScenarioError) as exc:
        print(f"DENIED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["decision"]["status"] == "ROUTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
