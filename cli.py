"""
CLI entry point for the installed `3nricher` command.

This is a thin wrapper so that `pip install -e .` exposes a `3nricher`
console script. All real logic lives in 3nricher.py.
"""
import importlib
import sys


def main() -> None:
    """Entry point for the `3nricher` console script."""
    mod = importlib.import_module("3nricher")

    if hasattr(mod, "main"):
        mod.main()
    else:
        print("ERROR: 3nricher.main() not found", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
