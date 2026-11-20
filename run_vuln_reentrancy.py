import csv
import os
import sys
import time
from pathlib import Path

from pathfinder.tasks import run_slither
import pandas as pd
import re

RUN_ID = time.strftime("%Y%m%d-%H%M%S")

CONFIGS = {
    "z3_only": {"Z3": "1", "PPT_MUTEX": "0", "PPT_AUTH": "0", "PPT_INIT": "0", "PPT_CEI": "0", "PPT_INHERIT": "0", "XCFG": "0"},
    "z3_ppt": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1", "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "1", "XCFG": "0"},
    "full": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1", "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "1", "XCFG": "1"},
    "full_no_mutex": {"Z3": "1", "PPT_MUTEX": "0", "PPT_AUTH": "1", "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "1", "XCFG": "1"},
    "full_no_auth": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "0", "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "1", "XCFG": "1"},
    "full_no_init": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1", "PPT_INIT": "0", "PPT_CEI": "1", "PPT_INHERIT": "1", "XCFG": "1"},
    "full_no_cei": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1", "PPT_INIT": "1", "PPT_CEI": "0", "PPT_INHERIT": "1", "XCFG": "1"},
    "full_no_inherit": {"Z3": "1", "PPT_MUTEX": "1", "PPT_AUTH": "1", "PPT_INIT": "1", "PPT_CEI": "1", "PPT_INHERIT": "0", "XCFG": "1"},
}

def extract_addr(fname):
    m = re.search(r'0x([a-fA-F0-9]{40})', fname)
    return m.group(0).lower() if m else None

# Load vulnerable addresses from labels
labels_path = Path('/mnt/data/sc-developer-study-1/Empirical Evaluation of Security Analyzers/Tools_Labels/Reentrancy_labels.csv')
labels_df = pd.read_csv(labels_path)
labels_df['addr'] = labels_df['contract_address'].apply(extract_addr)
vuln_addrs = set(labels_df[labels_df['label'] == 1]['addr'].tolist())

def main(limit_files: int | None = None):
    # Get only Reentrancy*1* files that are in vulnerable set
    all_files = sorted(Path('Solidity').glob('Reentrancy*1*.sol'))
    files = [f for f in all_files if extract_addr(f.name) in vuln_addrs]
    
    if limit_files:
        files = files[:limit_files]
    
    if not files:
        print("ERROR: no vulnerable Reentrancy .sol files found")
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
        writer.writerow(["file", "config", "status", "type", "detail"])

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
                        writer.writerow(["?", "?", "task_error", "", repr(e)[:300]])
                        summary["task_error"] += 1

            if res is None:
                if i % 50 == 0 or i == total_jobs:
                    print(f"  {i}/{total_jobs} done (ok={summary['ok']}, compile_error={summary['compile_error']}, timeout={summary['timeout']}, task_error={summary['task_error']}, findings={findings_count})")
                continue

            status = res.get("status", "?")
            summary[status] = summary.get(status, 0) + 1

            findings = res.get("findings") or []
            if not findings:
                writer.writerow([res["file"], res["config"], status, "", ""])
            else:
                for fd in findings:
                    ftype = fd.get("type", "?")
                    findings_count[ftype] = findings_count.get(ftype, 0) + 1
                    writer.writerow([res["file"], res["config"], status, ftype, fd.get("detail", "")])

            if i % 50 == 0 or i == total_jobs:
                print(f"  {i}/{total_jobs} done (ok={summary['ok']}, compile_error={summary['compile_error']}, timeout={summary['timeout']}, task_error={summary['task_error']}, findings={findings_count})")

    print("\nSummary:")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print(f"  findings: {findings_count}")
    print(f"\nWrote {OUT_CSV}")

if __name__ == "__main__":
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    main(limit_files=limit)
