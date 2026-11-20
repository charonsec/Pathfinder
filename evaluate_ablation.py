import csv
import pandas as pd
from pathlib import Path

# Load ground truth labels
labels_path = Path("/mnt/data/sc-developer-study-1/Empirical Evaluation of Security Analyzers/Tools_Labels/Reentrancy_labels.csv")
labels_df = pd.read_csv(labels_path)

# Create lookup: filename -> label (0=safe, 1=vuln)
# Our files are like: IntergerOU*0*0xADDRESS.sol but labels use Reentrancy*0*0xADDRESS.sol
# We need to match by address
def extract_addr(fname):
    # Extract 0x... from filename
    import re
    m = re.search(r'0x([a-fA-F0-9]{40})', fname)
    return m.group(0).lower() if m else None

labels_df['addr'] = labels_df['contract_address'].apply(extract_addr)
label_lookup = dict(zip(labels_df['addr'], labels_df['label']))

# Load ablation results
results_path = Path("ablation_results.csv")
results_df = pd.read_csv(results_path)

# Extract address from file path
results_df['addr'] = results_df['file'].apply(extract_addr)
results_df['gt_label'] = results_df['addr'].map(label_lookup)

# Drop rows without ground truth
results_df = results_df.dropna(subset=['gt_label'])
results_df['gt_label'] = results_df['gt_label'].astype(int)

# Our prediction: has finding (single or cross) = 1, else 0
results_df['pred'] = results_df['type'].notna().astype(int)

# Compute metrics per config
configs = results_df['config'].unique()
print(f"{'Config':<20} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} {'Prec':>6} {'Rec':>6} {'F1':>6}")
print("-" * 70)

for cfg in sorted(configs):
    sub = results_df[results_df['config'] == cfg]
    tp = ((sub['pred'] == 1) & (sub['gt_label'] == 1)).sum()
    fp = ((sub['pred'] == 1) & (sub['gt_label'] == 0)).sum()
    tn = ((sub['pred'] == 0) & (sub['gt_label'] == 0)).sum()
    fn = ((sub['pred'] == 0) & (sub['gt_label'] == 1)).sum()
    
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
    
    print(f"{cfg:<20} {tp:>4} {fp:>4} {tn:>4} {fn:>4} {prec:>6.3f} {rec:>6.3f} {f1:>6.3f}")

# Overall summary
print("\n=== Ground Truth Distribution ===")
print(results_df['gt_label'].value_counts().to_string())
print(f"\nTotal evaluated: {len(results_df)} contracts")
