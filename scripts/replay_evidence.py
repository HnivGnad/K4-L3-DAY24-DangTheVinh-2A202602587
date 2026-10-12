"""Reproduce synthetic before/after evidence against the localhost sink only.

Baseline mode explicitly invokes the vulnerable lab function. Never use real data.
"""
from pathlib import Path
import argparse
import json
from unittest.mock import patch

from agent import tools
from agent.llm import MockLLM, find_injection
from agent.loop import _naive_loop, run_once
from sink.sink import LOG_PATH, reset_log, run_in_background

QUERY = "Tổng hợp các ticket còn mở tuần này"
ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", action="store_true")
    args = parser.parse_args()
    server, thread = run_in_background()
    try:
        reset_log()
        if args.baseline:
            _naive_loop(QUERY, MockLLM())
        else:
            run_once(QUERY, mock=True, principal_id="dpo")
        name = "before" if args.baseline else "after"
        (ROOT / "reports" / f"attack-{name}.log").write_bytes(LOG_PATH.read_bytes())
        results = []
        for variant in range(1, 5):
            paths = sorted(tools.CORPUS_DIR.glob(f"ticket-90{variant}*.md"))
            docs = [{"id": p.name, "text": p.read_text(encoding="utf-8")} for p in paths]
            reset_log()
            with patch.object(tools, "search_docs", return_value=docs):
                if args.baseline:
                    _naive_loop(QUERY, MockLLM())
                else:
                    run_once(QUERY, mock=True, principal_id="dpo",
                             log_dir=ROOT / "reports" / f"variant-{variant}")
            evidence = ROOT / "reports" / f"variant-{variant}-{name}.log"
            evidence.write_bytes(LOG_PATH.read_bytes())
            results.append({"variant": variant, "files": [p.name for p in paths],
                            "recognized": find_injection("\n\n".join(d["text"] for d in docs)) is not None,
                            "sink_bytes": evidence.stat().st_size})
        (ROOT / "reports" / f"replay-{name}.json").write_text(
            json.dumps(results, indent=2), encoding="utf-8")
        print(json.dumps(results))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
