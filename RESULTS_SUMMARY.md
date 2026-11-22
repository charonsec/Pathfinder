## Corrected Ablation Results (125-contract dev subset of ScBench: 95 vuln + 30 non-vuln × 8 configs = 1000 contract-config pairs, 1797 finding-level rows)

| Config | TP | FP | TN | FN | Precision | Recall | F1 | Specificity | FPR |
|--------|----|----|----|----|-----------|--------|-----|-------------|-----|
| **full** | 92 | 45 | 19 | 3 | **0.672** | **0.968** | **0.793** | 0.297 | 0.703 |
| **full_no_auth** | 92 | 31 | 19 | 3 | **0.748** | **0.968** | **0.844** | **0.380** | **0.620** |
| **full_no_cei** | 92 | 45 | 19 | 3 | 0.672 | 0.968 | 0.793 | 0.297 | 0.703 |
| **full_no_init** | 92 | 45 | 19 | 3 | 0.672 | 0.968 | 0.793 | 0.297 | 0.703 |
| **full_no_mutex** | 92 | 45 | 19 | 3 | 0.672 | 0.968 | 0.793 | 0.297 | 0.703 |
| **full_no_inherit** | 92 | 45 | 19 | 3 | 0.672 | 0.968 | 0.793 | 0.297 | 0.703 |
| **z3_ppt** | 219 | 135 | 19 | 3 | 0.619 | 0.986 | 0.760 | 0.123 | 0.877 |
| **z3_only** | 219 | 241 | 18 | 3 | 0.476 | 0.986 | 0.642 | 0.069 | 0.931 |

### Key Findings (CONFIG BUG FIXED)

1. **PPTs suppress 196 FPs** (z3_only 241 → full 45) — **but also suppress 127 TPs** (219 → 92). Net F1 gain: +0.151 (0.642 → 0.793).

2. **Only AUTH fires uniquely** — `full_no_auth` recovers 14 FPs (31 vs 45) with identical TP (92). Mutex, Init, CEI, Inherit: **zero unique contribution** on this dataset.

3. **3 FNs across ALL configs** — detector misses these entirely. Need error analysis.

4. **High finding multiplicity** — 95 vuln contracts → 1014 vuln finding-level rows (10.7 findings/contract). TP/FP counts are finding-level, not contract-level.

5. **Cross-contract: 0 findings** — XCFG doesn't add value on this dataset.

6. **Abstain rate: 0%** — no Z3 UNKNOWN results; all constraints resolved SAT/UNSAT.

7. **Unit tests (intra_suppressor_tests.sol)**: All 5 suppressors verified to suppress their respective FPs; TP_Vulnerable correctly found in all configs.

### Caveats
- Metrics are **finding-level**, not contract-level (multiple findings per contract inflate TP/FP)
- Class imbalance: 1014 vuln rows vs 783 non-vuln rows (56% positive)
- FPR = 70% (45/64) for `full` — precision inflated by positive class imbalance
- Results on 125-contract dev subset; need evaluation on held-out test set

**Previous "fiction" results (F1=0.925) were WRONG** — config bug made all configs run with suppressors ON (detector reads `Z3`, `PPT_MUTEX`... but tasks.py passed `PATHFINDER_Z3`, `PATHFINDER_PPT_MUTEX`...).

---

## Next Steps

| Priority | Task | Status |
|----------|------|--------|
| 1 | Dev/test split (1000 → train/test) | Ready |
| 2 | Freeze config on dev, evaluate on test | Ready |
| 3 | Run Slither/Mythril/Securify baselines on test | Needs solc auto-switching |
| 4 | Update synopsis with real results + caveats | Ready |
| 5 | GitHub push + Docker artifact | Ready |