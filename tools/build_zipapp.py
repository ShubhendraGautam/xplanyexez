#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import stat
import tempfile
import zipapp
from pathlib import Path


def build(output: Path) -> Path:
    repository = Path(__file__).resolve().parents[1]
    source = repository / "src"
    if not (source / "hwprobe/__main__.py").is_file():
        raise RuntimeError(f"hwprobe package not found below {source}")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)

    def include(path: Path) -> bool:
        return "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"}

    try:
        with tempfile.TemporaryDirectory(prefix=".hwprobe-build.", dir=output.parent) as staging_name:
            staging = Path(staging_name)
            shutil.copytree(source / "hwprobe", staging / "hwprobe")
            shutil.copy2(repository / "LICENSE", staging / "LICENSE")
            zipapp.create_archive(
                staging,
                target=temporary,
                interpreter="/usr/bin/env python3",
                main="hwprobe.cli:main",
                compressed=True,
                filter=include,
            )
            temporary.chmod(temporary.stat().st_mode | stat.S_IXUSR)
            os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the standalone Xplanyexez scanner")
    parser.add_argument("--output", type=Path, default=Path("dist/hwprobe.pyz"))
    args = parser.parse_args()
    output = build(args.output)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
