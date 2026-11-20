"""
Ablation producer: dispatches Slither+PathFinder runs over ScBench
in 8 configurations and collects results into ablation_results.csv.

Usage:
    python ablation_producer.py [N]   # N = limit to first N .sol files (omit for all)
"""

import csv
import os
import sys
from pathlib import Path

from pathfinder.tasks import run_slither
import time

RUN_ID = time.strftime("%Y%m%d-%H%M%S")

SOLIDITY_DIR = Path(
    "/mnt/data/sc-developer-study-1/"
    "Empirical Evaluation of Security Analyzers/Solidity"
)
OUT_CSV = Path("ablation_results.csv")

CONFIGS = {
    "z3_only": {
        "Z3": "1", "PPT_MUTEX": "0", "PPT_AUTH": "0",
        "PPT_INIT": "0", "PPT_CEI": "0", "PPT_INHERIT": "0",
        "XCFG": "0",
    },
    "z3_ppt": {
        "Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1",
        "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "1",
        "XCFG": "0",
    },
    "full": {
        "Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1",
        "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "1",
        "XCFG": "1",
    },
    "full_no_mutex": {
        "Z3": "1", "PPT_MUTEX": "0", "PPT_AUTH": "1",
        "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "1",
        "XCFG": "1",
    },
    "full_no_auth": {
        "Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "0",
        "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "1",
        "XCFG": "1",
    },
    "full_no_init": {
        "Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1",
        "PPT_INIT": "0", "PPT_CEI": "1", "PPT_INHERIT": "1",
        "XCFG": "1",
    },
    "full_no_cei": {
        "Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1",
        "PPT_INIT": "1", "PPT_CEI": "0", "PPT_INHERIT": "1",
        "XCFG": "1",
    },
    "full_no_inherit": {
        "Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1",
        "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "0",
        "XCFG": "1",
    },
}


def _collect_files(limit: int | None) -> list[Path]:
    files = sorted(SOLIDITY_DIR.glob("*.sol"))
    if limit is not None:
        files = files[:limit]
    return files


def main(limit_files: int | None = None):
    files = _collect_files(limit_files)
    if not files:
        print(f"ERROR: no .sol files found under {SOLIDITY_DIR}")
        sys.exit(1)

    total_jobs = len(files) * len(CONFIGS)
    print(f"Dispatching {total_jobs} tasks "
          f"for {len(files)} files × {len(CONFIGS)} configs")

    # Dispatch all tasks up-front so the worker queue is filled
    jobs = []
    for f in files:
        for name, env in CONFIGS.items():
            task_id = f"{RUN_ID}-{f.stem[:40]}-{name}"
            jobs.append(run_slither.apply_async(
                args=(str(f), name, env),
                task_id=task_id,
            ))
    summary = {
        "ok": 0,
        "compile_error": 0,
        "timeout": 0,
        "task_error": 0,
    }
    findings_count = {"single": 0, "cross": 0}

    with OUT_CSV.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["file", "config", "status", "type", "detail"])

        for i, job in enumerate(jobs, 1):
            res = None

            # Two attempts: initial get, then a retry if the result
            # backend was transiently unavailable (e.g. Redis flush race).
            for attempt in (1, 2):
                try:
                    res = job.get(timeout=150)
                    break
                except KeyboardInterrupt:
                    print(f"\nInterrupted at {i}/{total_jobs}")
                    return
                except Exception as e:
                    if attempt == 2:
                        writer.writerow(
                            ["?", "?", "task_error", "", repr(e)[:300]]
                        )
                        summary["task_error"] += 1
                    # else: fall through and retry once
            if res is None:
                if i % 50 == 0 or i == total_jobs:
                    print(
                        f"  {i}/{total_jobs} done "
                        f"(ok={summary['ok']}, "
                        f"compile_error={summary['compile_error']}, "
                        f"timeout={summary['timeout']}, "
                        f"task_error={summary['task_error']}, "
                        f"findings={findings_count})"
                    )
                continue

            status = res.get("status", "?")
            summary[status] = summary.get(status, 0) + 1

            findings = res.get("findings") or []
            if not findings:
                writer.writerow(
                    [res["file"], res["config"], status, "", ""]
                )
            else:
                for fd in findings:
                    ftype = fd.get("type", "?")
                    findings_count[ftype] = findings_count.get(ftype, 0) + 1
                    writer.writerow(
                        [res["file"], res["config"], status,
                         ftype, fd.get("detail", "")]
                    )

            if i % 50 == 0 or i == total_jobs:
                print(
                    f"  {i}/{total_jobs} done "
                    f"(ok={summary['ok']}, "
                    f"compile_error={summary['compile_error']}, "
                    f"timeout={summary['timeout']}, "
                    f"task_error={summary['task_error']}, "
                    f"findings={findings_count})"
                )

    print("\nSummary:")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print(f"  findings: {findings_count}")
    print(f"\nWrote {OUT_CSV}")


if __name__ == "__main__":
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    main(limit_files=limit)