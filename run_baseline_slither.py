#!/usr/bin/env python3
"""Run Slither baseline on test set contracts."""

import subprocess
import csv
from pathlib import Path
import re

# Get test contract addresses
import pandas as pd
df = pd.read_csv('ablation_test.csv')
addrs = df['file'].str.extract(r'(0x[a-fA-F0-9]{40})')[0].unique()

labels_path = Path("sc-developer-study-1/Empirical Evaluation of Security Analyzers/Tools_Labels/Reentrancy_labels.csv")
labels_df = pd.read_csv(labels_path)
def extract_addr(fname):
    m = re.search(r'0x([a-fA-F0-9]{40})', fname)
    return m.group(0).lower() if m else None
labels_df['addr'] = labels_df['contract_address'].apply(extract_addr)
label_lookup = dict(zip(labels_df['addr'], labels_df['label']))

OUT_CSV = Path("baseline_slither_test.csv")
with OUT_CSV.open("w", newline="") as fh:
    writer = csv.writer(fh)
    writer.writerow(["file", "addr", "gt_label", "slither_finding", "slither_detail"])

    for addr in addrs:
        # Find the contract file
        files = list(Path("Solidity").glob(f"Reentrancy*1*{addr}.sol")) + list(Path("Solidity").glob(f"Reentrancy*0*{addr}.sol"))
        if not files:
            print(f"File not found for {addr}")
            continue
        f = files[0]
        gt = label_lookup.get(addr, -1)
        
        # Run slither with reentrancy detector
        try:
            result = subprocess.run(
                ["slither", str(f), "--detect", "reentrancy-eth", "reentrancy-no-eth"],
                capture_output=True, text=True, timeout=120
            )
            findings = []
            for line in result.stdout.splitlines():
                if "Reentrancy" in line and ("eth" in line.lower() or "no-eth" in line.lower()):
                    findings.append(line.strip())
            
            pred = 1 if findings else 0
            detail = "; ".join(findings) if findings else ""
            writer.writerow([str(f), addr, gt, pred, detail])
            print(f"{addr} (gt={gt}): slither={'FP' if pred and gt==0 else 'TP' if pred and gt==1 else 'FN' if not pred and gt==1 else 'TN'} ({len(findings)} findings)")
        except subprocess.TimeoutExpired:
            writer.writerow([str(f), addr, gt, "timeout", ""])
            print(f"{addr}: TIMEOUT")
        except Exception as e:
            writer.writerow([str(f), addr, gt, "error", str(e)[:200]])
            print(f"{addr}: ERROR {e}")

print(f"\nSaved to {OUT_CSV}")
