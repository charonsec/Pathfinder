import fcntl
import os
import re
import json
import subprocess
import shutil
from pathlib import Path

from .celery_app import app

# Use env vars for portability, fallback to local .venv
SLITHER_BIN = os.getenv("PATHFINDER_SLITHER_BIN") or shutil.which("slither") or str(
    Path(__file__).resolve().parent.parent / ".venv" / "bin" / "slither"
)
# Check both project .venv and global solc-select locations
SOLC_ARTIFACTS = Path(
    os.getenv("PATHFINDER_SOLC_ARTIFACTS")
    or str(Path.home() / ".solc-select" / "artifacts")
)
GLOBAL_SOLC_ARTIFACTS = Path.home() / ".solc-select" / "artifacts"
SOLC_LOCK = "/tmp/solc_select.lock"


def _solc_binary(version: str) -> Path | None:
    """
    Return the executable path for a solc version.
    Handles both layouts:
      artifacts/solc-X.Y.Z            (flat, older solc-select)
      artifacts/solc-X.Y.Z/solc-X.Y.Z (nested, newer solc-select)
    Checks both project and global solc-select locations.
    """
    for artifacts in (SOLC_ARTIFACTS, GLOBAL_SOLC_ARTIFACTS):
        base = artifacts / f"solc-{version}"
        nested = base / f"solc-{version}"
        if nested.is_file():
            return nested
        if base.is_file():
            return base
    return None


def _detect_pragma(sol_file: str) -> str | None:
    try:
        with open(sol_file, "r", errors="ignore") as fh:
            head = fh.read(4000)
    except OSError:
        return None
    m = re.search(r"pragma\s+solidity\s+([^;]+);", head)
    return m.group(1).strip() if m else None


def _resolve_solc_path(pragma_expr: str | None) -> str | None:
    if not pragma_expr:
        return None
    # Use solc-select to find the best matching version
    try:
        result = subprocess.run(
            ["solc-select", "list", "--installed"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            installed = result.stdout.strip().split()
            # Filter by pragma (simplified: use highest installed)
            if installed:
                return str(_solc_binary(installed[-1]))
    except Exception:
        pass
    # Fallback: try regex extraction
    versions = re.findall(r"\d+\.\d+\.\d+", pragma_expr)
    if not versions:
        return None

    candidates = []
    for v in versions:
        p = _solc_binary(v)
        if p is not None:
            candidates.append((v, p))

    if not candidates:
        return None

    candidates.sort(key=lambda x: tuple(int(p) for p in x[0].split(".")))
    return str(candidates[-1][1])


def _ensure_installed(version: str) -> bool:
    if _solc_binary(version) is not None:
        return True

    with open(SOLC_LOCK, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            if _solc_binary(version) is not None:
                return True
            r = subprocess.run(
                ["solc-select", "install", version],
                capture_output=True, text=True, timeout=180,
            )
            return r.returncode == 0 and _solc_binary(version) is not None
        except Exception:
            return False
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _parse_findings(stdout: str, stderr: str):
    findings = []
    # First priority: parse structured JSON output (PATHFINDER_JSON:)
    for line in (stdout + "\n" + stderr).splitlines():
        line = line.strip()
        if line.startswith("PATHFINDER_JSON:"):
            try:
                json_str = line[len("PATHFINDER_JSON:"):]
                record = json.loads(json_str)
                # Only count SAT as positive finding
                if record.get("sat_finding"):
                    findings.append({
                        "type": record.get("config", "single-contract"),
                        "detail": record.get("detail", ""),
                        "z3_result": record.get("z3_result"),
                        "sat_finding": True,
                        "unknown_finding": False
                    })
                elif record.get("unknown_finding"):
                    findings.append({
                        "type": record.get("config", "single-contract"),
                        "detail": record.get("detail", ""),
                        "z3_result": record.get("z3_result"),
                        "sat_finding": False,
                        "unknown_finding": True
                    })
            except json.JSONDecodeError:
                pass
    # Fallback: legacy human-readable parsing (for compatibility)
    if not findings:
        for line in (stdout + "\n" + stderr).splitlines():
            line = line.strip()
            if line.startswith("Reentrancy (single-contract"):
                findings.append({"type": "single", "detail": line, "z3_result": "UNKNOWN", "sat_finding": False, "unknown_finding": False})
            elif line.startswith("Reentrancy (cross-contract"):
                findings.append({"type": "cross", "detail": line, "z3_result": "UNKNOWN", "sat_finding": False, "unknown_finding": False})
    return findings


@app.task(bind=True, max_retries=0)
def run_slither(self, sol_file: str, config_name: str, config_env: dict,
                timeout: int = 60):
    env = os.environ.copy()
    for k, v in config_env.items():
        env[k] = v
    env["Z3_TIMEOUT_MS"] = str(timeout * 1000)

    cmd = [SLITHER_BIN, sol_file, "--detect", "pathfinder"]

    pragma = _detect_pragma(sol_file)
    solc_path = _resolve_solc_path(pragma)
    if solc_path is None and pragma:
        m = re.search(r"\d+\.\d+\.\d+", pragma)
        if m and _ensure_installed(m.group(0)):
            solc_path = str(_solc_binary(m.group(0)))
    if solc_path:
        cmd += ["--solc", solc_path]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout + 30, env=env,
        )
    except subprocess.TimeoutExpired:
        return {"file": sol_file, "config": config_name,
                "status": "timeout", "findings": []}

    # Slither returns:
    #   0 = no issues found
    #   1 = issues found (but no compilation errors)
    #   255 = issues found (legacy behavior)
    # Other non-zero codes = compilation/runtime errors
    findings = _parse_findings(proc.stdout, proc.stderr)
    if proc.returncode not in (0, 1, 255):
        # Actual compilation/runtime error
        return {"file": sol_file, "config": config_name,
                "status": "compile_error",
                "error": proc.stderr[-400:], "findings": []}

    # Extract structured finding data for evaluation CSV
    sat_findings = [f for f in findings if f.get("sat_finding")]
    unknown_findings = [f for f in findings if f.get("unknown_finding")]
    
    return {"file": sol_file, "config": config_name, "status": "ok",
            "findings": findings,
            "sat_count": len(sat_findings),
            "unknown_count": len(unknown_findings),
            "raw_stdout": proc.stdout[-2000:]}