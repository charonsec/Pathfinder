#!/usr/bin/env python3
"""
Contract-level evaluation for PathFinder ablation study.
Aggregates finding-level results to per-contract predictions.
"""

import pandas as pd
from pathlib import Path
import sys
import argparse
import re

parser = argparse.ArgumentParser()
parser.add_argument("--input", required=True, help="Input CSV file")
args = parser.parse_args()

# Load ground truth labels
labels_path = Path("sc-developer-study-1/Empirical Evaluation of Security Analyzers/Tools_Labels/Reentrancy_labels.csv")
if not labels_path.exists():
    print(f"ERROR: Labels file not found at {labels_path}")
    sys.exit(1)

labels_df = pd.read_csv(labels_path)

def extract_addr(fname):
    m = re.search(r'0x([a-fA-F0-9]{40})', fname)
    return m.group(0).lower() if m else None

labels_df['addr'] = labels_df['contract_address'].apply(extract_addr)
label_lookup = dict(zip(labels_df['addr'], labels_df['label']))

# Load ablation results
results_path = Path(args.input)
if not results_path.exists():
    print(f"ERROR: Results file not found at {results_path}")
    sys.exit(1)

results_df = pd.read_csv(results_path)
results_df['addr'] = results_df['file'].apply(extract_addr)
results_df['gt_label'] = results_df['addr'].map(label_lookup)
results_df = results_df.dropna(subset=['gt_label'])
results_df['gt_label'] = results_df['gt_label'].astype(int)

# Fill NaN
results_df['sat_finding'] = results_df['sat_finding'].fillna(False)
results_df['unknown_finding'] = results_df['unknown_finding'].fillna(False)

print(f"=== Contract-Level Evaluation ({args.input}) ===")
print(f"Total finding-level rows: {len(results_df)}")

# Contract-level aggregation: a contract is POSITIVE if ANY finding has sat_finding=True
contract_results = []

for addr, group in results_df.groupby('addr'):
    gt = group['gt_label'].iloc[0]
    configs = group['config'].unique()
    
    for cfg in configs:
        cfg_group = group[group['config'] == cfg]
        # Contract is predicted vulnerable if ANY finding is SAT
        pred = cfg_group['sat_finding'].any()
        # Count findings for info
        n_sat = cfg_group['sat_finding'].sum()
        n_unknown = cfg_group['unknown_finding'].sum()
        n_total = len(cfg_group)
        
        contract_results.append({
            'addr': addr,
            'config': cfg,
            'gt': gt,
            'pred': int(pred),
            'n_sat': n_sat,
            'n_unknown': n_unknown,
            'n_findings': n_total
        })

contract_df = pd.DataFrame(contract_results)

print(f"Unique contracts: {contract_df['addr'].nunique()}")
print(f"Contract-config pairs: {len(contract_df)}")
print(f"Ground truth distribution:\n{contract_df['gt'].value_counts().to_string()}")

# Metrics per config
configs = sorted(contract_df['config'].unique())
print(f"\n{'Config':<20} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} {'Prec':>6} {'Rec':>6} {'F1':>6} {'Spec':>6}")
print("-" * 80)

for cfg in configs:
    sub = contract_df[contract_df['config'] == cfg]
    tp = ((sub['pred'] == 1) & (sub['gt'] == 1)).sum()
    fp = ((sub['pred'] == 1) & (sub['gt'] == 0)).sum()
    tn = ((sub['pred'] == 0) & (sub['gt'] == 0)).sum()
    fn = ((sub['pred'] == 0) & (sub['gt'] == 1)).sum()
    
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0
    
    print(f"{cfg:<20} {tp:>4} {fp:>4} {tn:>4} {fn:>4} {prec:>6.3f} {rec:>6.3f} {f1:>6.3f} {spec:>6.3f}")

# Show FN contracts (missed vulnerabilities)
fn_contracts = contract_df[(contract_df['pred'] == 0) & (contract_df['gt'] == 1)]
if len(fn_contracts) > 0:
    print(f"\n=== FALSE NEGATIVES (missed vuln contracts) ===")
    for _, row in fn_contracts.iterrows():
        print(f"  {row['addr']} | config={row['config']} | findings={row['n_findings']} | sat={row['n_sat']} | unknown={row['n_unknown']}")

# Show FP contracts (false alarms)
fp_contracts = contract_df[(contract_df['pred'] == 1) & (contract_df['gt'] == 0)]
if len(fp_contracts) > 0:
    print(f"\n=== FALSE POSITIVES (false alarms) ===")
    fp_summary = fp_contracts.groupby('config')['addr'].nunique()
    for cfg, count in fp_summary.items():
        print(f"  {cfg}: {count} contracts")

# Save contract-level results
out_path = Path(args.input).with_name(Path(args.input).stem + "_contract_level.csv")
contract_df.to_csv(out_path, index=False)
print(f"\nSaved contract-level results to {out_path}")