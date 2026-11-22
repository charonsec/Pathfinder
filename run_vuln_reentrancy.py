#!/usr/bin/env python3
"""
Run ablation on vulnerable Reentrancy contracts.
Uses shared config from pathfinder.config
"""

import csv
import os
import sys
import time
from pathlib import Path

from pathfinder.tasks import run_slither
from pathfinder.config import (
    CONFIGS, get_vuln_files
)


def main(limit_files: int | None = None):
    RUN_ID = time.strftime("%Y%m%d-%H%M%S")
    files = get_vuln_files(limit_files)

    if not files:
        print("ERROR: no vulnerable Reentrancy .sol files found")
        print(f"  Dataset dir: {os.getenv('PATHFINDER_DATASET_DIR', './Solidity')}")
        print(f"  Labels path: {os.getenv('PATHFINDER_LABELS_PATH', '/mnt/data/...')}")
        sys.exit(1)

    total_jobs = len(files) * len(CONFIGS)
    print(f"Dispatching {total_jobs} tasks for {len(files)} vulnerable Reentrancy files × {len(CONFIGS)} configs")

    OUT_CSV = Path("ablation_vuln_reentrancy_results.csv")

    # Dispatch all tasks
    jobs = []
    for f in files:
        for name, env in CONFIGS.items():
            task_id = f"{RUN_ID}-{f.stem[:40]}-{name}"
            jobs.append(run_slither.apply_async(
                args=(str(f), name, env),
                task_id=task_id,
            ))

    summary = {"ok": 0, "compile_error": 0, "timeout": 0, "task_error": 0}
    findings_count = {"single": 0, "cross": 0}

    with OUT_CSV.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["file", "config", "status", "type", "detail", "z3_result", "sat_finding", "unknown_finding"])

        for i, job in enumerate(jobs, 1):
            res = None
            for attempt in (1, 2):
                try:
                    res = job.get(timeout=180)
                    break
                except KeyboardInterrupt:
                    print(f"\nInterrupted at {i}/{total_jobs}")
                    return
                except Exception as e:
                    if attempt == 2:
                        writer.writerow(["?", "?", "task_error", "", "", "", "", ""])
                        summary["task_error"] += 1

            if res is None:
                if i % 50 == 0 or i == total_jobs:
                    print(f"  {i}/{total_jobs} done (ok={summary['ok']}, compile_error={summary['compile_error']}, timeout={summary['timeout']}, task_error={summary['task_error']}, findings={findings_count})")
                continue

            status = res.get("status", "?")
            summary[status] = summary.get(status, 0) + 1

            findings = res.get("findings") or []
            if not findings:
                writer.writerow([res["file"], res["config"], status, "", "", "", "", ""])
            else:
                for fd in findings:
                    ftype = fd.get("type", "?")
                    findings_count[ftype] = findings_count.get(ftype, 0) + 1
                    writer.writerow([res["file"], res["config"], status, ftype, fd.get("detail", ""), fd.get("z3_result", ""), fd.get("sat_finding", False), fd.get("unknown_finding", False)])

            if i % 50 == 0 or i == total_jobs:
                print(f"  {i}/{total_jobs} done (ok={summary['ok']}, compile_error={summary['compile_error']}, timeout={summary['timeout']}, task_error={summary['task_error']}, findings={findings_count})")

    print("\nSummary:")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print(f"  findings: {findings_count}")
    print(f"\nWrote {OUT_CSV}")


if __name__ == "__main__":
    RUN_ID = time.strftime("%Y%m%d-%H%M%S")
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    main(limit_files=limit)