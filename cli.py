"""
CLI entry point for the installed `3nricher` command.

This is a thin wrapper so that `pip install -e .` exposes a `3nricher`
console script. All real logic lives in 3nricher.py.

Note: `3nricher.py` starts with a digit, which is not a valid Python
module name for setuptools `py-modules`. We load it dynamically from
its file path instead.
"""
import importlib.util
import sys
from pathlib import Path


def _load_3nricher():
    """Load 3nricher.py from disk as a module."""
    module_path = Path(__file__).parent / "3nricher.py"

    if not module_path.exists():
        print(f"ERROR: {module_path} not found", file=sys.stderr)
        sys.exit(1)

    spec = importlib.util.spec_from_file_location("3nricher", module_path)
    if spec is None or spec.loader is None:
        print(f"ERROR: could not load {module_path}", file=sys.stderr)
        sys.exit(1)

    module = importlib.util.module_from_spec(spec)
    sys.modules["3nricher"] = module
    spec.loader.exec_module(module)
    return module


def main() -> None:
    """Entry point for the `3nricher` console script."""
    mod = _load_3nricher()

    if hasattr(mod, "main"):
        mod.main()
    else:
        print("ERROR: 3nricher.main() not found", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
