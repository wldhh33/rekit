"""让 `python -m rekit` 等价于 `rekit`。"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
