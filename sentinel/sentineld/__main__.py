"""sentineld entry point: python -I -m sentineld [options]"""
import argparse
import logging
import os
import sys

from .daemon import Config, Daemon

HERE = os.path.dirname(os.path.abspath(__file__))
SENTINEL_DIR = os.path.dirname(HERE)
REPO_DIR = os.path.dirname(SENTINEL_DIR)


def parse_test_case(s):
    pid, _, level = s.partition(":")
    if not pid.isdigit():
        raise argparse.ArgumentTypeError("expected PID or PID:LEVEL")
    level = (level or "SUSPECT").upper()
    if level not in ("WATCH", "SUSPECT", "HOSTILE"):
        raise argparse.ArgumentTypeError("level must be WATCH, SUSPECT or HOSTILE")
    return int(pid), level


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sentineld", description="Hodometer Sentinel daemon (SENTINEL.md)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", default=True, help="log kill and block, never send them (default)")
    mode.add_argument("--live", action="store_true", help="send kill and block to Hodometer")
    ap.add_argument("--port", type=int, default=48201)
    ap.add_argument("--model", default="claude-sonnet-5-5", help="Sentinel and SUSPECT+ investigators")
    ap.add_argument("--watch-model", default=None, help="WATCH-level investigators (default: same as --model; e.g. claude-haiku-5-5)")
    ap.add_argument("--effort", default="medium", choices=["low", "medium", "high", "xhigh", "max"])
    ap.add_argument("--max-investigators", type=int, default=4)
    ap.add_argument("--state", default=os.path.join(SENTINEL_DIR, "state"), help="ledger, logs, transcripts")
    ap.add_argument("--prompts", default=os.path.join(REPO_DIR, "SENTINEL.md"), help="SENTINEL.md with the prompts")
    ap.add_argument("--no-models", action="store_true", help="daemon only: score and log, no Claude sessions")
    ap.add_argument("--no-fallback", action="store_true", help="do not use the server-side refusal fallback beta")
    ap.add_argument("--heartbeat", type=int, default=60, help="seconds between heartbeats to Sentinel")
    ap.add_argument("--batch", type=int, default=5, help="seconds to batch non-urgent items")
    ap.add_argument("--context-limit", type=int, default=100000, help="restart Sentinel's conversation above this many tokens")
    ap.add_argument("--capture", type=int, default=300, help="seconds of pcapng capture at SUSPECT")
    ap.add_argument("--popup", action="store_true", help="also show alerts and incidents in a message box")
    ap.add_argument("--test-case", action="append", type=parse_test_case, default=[], metavar="PID[:LEVEL]",
                    help="force a case for this pid once it is inspected (dry-run testing)")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)

    os.makedirs(a.state, exist_ok=True)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        handlers=[logging.FileHandler(os.path.join(a.state, "sentinel.log"), encoding="utf-8")])
    if a.verbose:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logging.getLogger().addHandler(h)
    logging.getLogger("httpx2").setLevel(logging.WARNING)
    logging.getLogger("httpcore2").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)

    cfg = Config(port=a.port, dry_run=not a.live, model=a.model, watch_model=a.watch_model, effort=a.effort,
                 max_investigators=a.max_investigators, state_dir=a.state, prompts_path=a.prompts,
                 use_fallback=not a.no_fallback, models_enabled=not a.no_models, popup=a.popup,
                 heartbeat_s=a.heartbeat, batch_s=a.batch, context_limit=a.context_limit, capture_s=a.capture,
                 test_cases=a.test_case)
    Daemon(cfg).run()


if __name__ == "__main__":
    main()
