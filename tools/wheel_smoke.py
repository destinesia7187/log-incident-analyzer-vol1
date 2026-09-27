"""Install the built wheel in an isolated environment and run outside the source tree."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    wheels = sorted((ROOT / "dist").glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Build one wheel with uv build first.")
    work = Path(os.environ.get("LIA_WHEEL_WORK", ROOT / "reports" / "wheel-smoke")).absolute()
    if work.exists():
        raise SystemExit("Choose a fresh LIA_WHEEL_WORK directory.")
    envpath = work / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(envpath)], check=True)
    python = envpath / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(
        [str(python), "-m", "pip", "install", "--require-hashes", "-r", str(ROOT / "requirements.lock.txt")],
        check=True,
    )
    subprocess.run([str(python), "-m", "pip", "install", "--no-deps", str(wheels[0])], check=True)
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [str(python), "-m", "lia.cli", "demo", "--output", str(work / "demo")],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    report = {
        "python": str(python),
        "demo": json.loads(result.stdout),
        "wheel": wheels[0].name,
        "wheel_sha256": hashlib.sha256(wheels[0].read_bytes()).hexdigest(),
        "passed": True,
    }
    (ROOT / "reports" / "wheel-smoke.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
