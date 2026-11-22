#!/usr/bin/env python3
"""
Evaluation script for PathFinder ablation study.

Reads ablation_results.csv and Reentrancy_labels.csv, produces:
- Confusion matrix per config (TP, FP, TN, FN)
- Precision, Recall, F1, Specificity
- Abstain count (Z3 UNKNOWN results)
- Matched vs unmatched contract counts
"""

import csv
import pandas as pd
from pathlib import Path
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--input", default="ablation_combined_fixed.csv", help="Input CSV file")
args = parser.parse_args()

# Load ground truth labels
labels_path = Path("sc-developer-study-1/Empirical Evaluation of Security Analyzers/Tools_Labels/Reentrancy_labels.csv")
if not labels_path.exists():
    print(f"ERROR: Labels file not found at {labels_path}")
    sys.exit(1)

labels_df = pd.read_csv(labels_path)

# Create lookup: address -> label (0=safe, 1=vuln)
def extract_addr(fname):
    import re
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

# Extract address from file path
results_df['addr'] = results_df['file'].apply(extract_addr)
results_df['gt_label'] = results_df['addr'].map(label_lookup)

# Track matched vs unmatched
matched = results_df['gt_label'].notna().sum()
unmatched = results_df['gt_label'].isna().sum()
print(f"=== Dataset Matching ===")
print(f"Total result rows: {len(results_df)}")
print(f"Matched to ground truth: {matched}")
print(f"Unmatched (no ground truth): {unmatched}")
print(f"Expected SCBENCH reentrancy contracts: 185 (95 vuln, 90 safe)")

# Drop rows without ground truth
results_df = results_df.dropna(subset=['gt_label'])
results_df['gt_label'] = results_df['gt_label'].astype(int)

# Our prediction: SAT finding = 1 (positive), UNKNOWN/UNSAT/none = 0 (negative or abstain)
# sat_finding is boolean column from CSV
results_df['sat_finding'] = results_df['sat_finding'].fillna(False)
results_df['unknown_finding'] = results_df['unknown_finding'].fillna(False)
results_df['pred'] = results_df['sat_finding'].astype(int)
results_df['abstain'] = results_df['unknown_finding'].astype(int)

# Compute metrics per config
configs = results_df['config'].unique()
print(f"\n{'Config':<20} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} {'Abstain':>8} {'Prec':>6} {'Rec':>6} {'F1':>6} {'Spec':>6}")
print("-" * 90)

overall_tp = overall_fp = overall_tn = overall_fn = overall_abstain = 0

for cfg in sorted(configs):
    sub = results_df[results_df['config'] == cfg]
    
    # Only compute on non-abstained (SAT vs no-finding)
    eval_sub = sub[sub['abstain'] == 0]
    abstain_count = sub['abstain'].sum()
    
    tp = ((eval_sub['pred'] == 1) & (eval_sub['gt_label'] == 1)).sum()
    fp = ((eval_sub['pred'] == 1) & (eval_sub['gt_label'] == 0)).sum()
    tn = ((eval_sub['pred'] == 0) & (eval_sub['gt_label'] == 0)).sum()
    fn = ((eval_sub['pred'] == 0) & (eval_sub['gt_label'] == 1)).sum()
    
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0
    
    overall_tp += tp
    overall_fp += fp
    overall_tn += tn
    overall_fn += fn
    overall_abstain += abstain_count
    
    print(f"{cfg:<20} {tp:>4} {fp:>4} {tn:>4} {fn:>4} {abstain_count:>8} {prec:>6.3f} {rec:>6.3f} {f1:>6.3f} {spec:>6.3f}")

# Overall summary (excluding abstained)
print("-" * 90)
prec_o = overall_tp / (overall_tp + overall_fp) if (overall_tp + overall_fp) > 0 else 0
rec_o = overall_tp / (overall_tp + overall_fn) if (overall_tp + overall_fn) > 0 else 0
f1_o = 2 * prec_o * rec_o / (prec_o + rec_o) if (prec_o + rec_o) > 0 else 0
spec_o = overall_tn / (overall_tn + overall_fp) if (overall_tn + overall_fp) > 0 else 0
print(f"{'OVERALL':<20} {overall_tp:>4} {overall_fp:>4} {overall_tn:>4} {overall_fn:>4} {overall_abstain:>8} {prec_o:>6.3f} {rec_o:>6.3f} {f1_o:>6.3f} {spec_o:>6.3f}")

print(f"\n=== Ground Truth Distribution ===")
print(results_df['gt_label'].value_counts().to_string())
print(f"\nTotal evaluated (non-abstained): {overall_tp + overall_fp + overall_tn + overall_fn}")
print(f"Total abstained (Z3 UNKNOWN): {overall_abstain}")
print(f"Abstain rate: {overall_abstain / len(results_df) * 100:.1f}%")