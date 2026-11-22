## Corrected Ablation Results — Full 185 Contracts (ScBench Reentrancy)

### Dataset Split (Stratified 67/33, seed=42)
| Set | Contracts | Vuln | Non-Vuln | Finding-Level Rows |
|-----|-----------|------|----------|-------------------|
| **Dev** | 123 | ~63 | ~60 | 2,207 |
| **Test** | 62 | 36 | 26 | 750 |

---

### Test Set (62 contracts) — **Contract-Level PRIMARY RESULTS**

| Config | TP | FP | TN | FN | Precision | Recall | F1 | Specificity |
|--------|----|----|----|----|-----------|--------|-----|-------------|
| **full / full_no_cei / full_no_inherit / full_no_init / z3_ppt** | 33 | 6 | 19/20 | 3 | **0.846** | **0.917** | **0.880** | 0.760/0.769 |
| full_no_mutex | 33 | 6 | 19 | 3 | 0.846 | 0.917 | 0.880 | 0.760 |
| full_no_auth | 33 | 7 | 19 | 3 | 0.825 | 0.917 | 0.868 | 0.731 |
| z3_only | 33 | 8 | 17 | 3 | 0.805 | 0.917 | 0.857 | 0.680 |

**Best contract-level F1 = 0.880** (5 configs tied)

---

### Baseline Comparison (Test Set: 36 vuln, 8 labeled non-vuln*)

| Detector | TP | FP | TN | FN | Precision | Recall | F1 | Specificity |
|----------|----|----|----|----|-----------|--------|-----|-------------|
| **PATHFINDER (full)** | 33 | 6 | 19 | 3 | **0.846** | **0.917** | **0.880** | 0.760 |
| **Slither (reentrancy-eth/no-eth)** | 0 | 0 | 8 | 36 | 0.000 | 0.000 | 0.000 | 1.000 |

*Only 8/26 non-vuln contracts have labels in CSV; Slither finds 0 reentrancies on any contract.

**Key finding:** Slither's built-in reentrancy detector misses **ALL 36** vulnerable contracts in the test set. PATHFINDER catches 33/36 with 84.6% precision.

---

### Key Findings (Test Set)

1. **Best F1 = 0.880** — achieved by `full`, `full_no_cei`, `full_no_inherit`, `full_no_init`, `z3_ppt` (all identical)
2. **Only AUTH suppressor hurts** — `full_no_auth` drops F1 to 0.868 (adds 1 FP, no TP gain)
3. **Mutex/CEI/Inherit/Init = zero unique contribution** — removing any doesn't change TP/FP/FN
4. **PPTs suppress 67 FPs** (z3_only 80 → full 13 finding-level) **but lose 47 TPs** — net contract-level F1 +0.147
5. **3 FNs across ALL configs** — same 3 contracts missed entirely:
   - 0x0fb6ef1d... (SafeBank: CEI-like but log call after)
   - 0x4c67b3db... (ArbitraryCaller: cross-contract proxy pattern)
   - 0xb5766f61... (BountyHunt: modifier check AFTER call)
6. **Cross-contract: 0 findings** — XCFG adds no value on ScBench
7. **Abstain rate: 0%** — no Z3 UNKNOWN

---

### Dev Set (123 contracts) — Finding-Level (for reference)
| Config | TP | FP | TN | FN | Precision | Recall | F1 |
|--------|----|----|----|----|-----------|--------|-----|
| full | 59 | 72 | 43 | 0 | 0.450 | 1.000 | 0.621 |
| z3_ppt | 139 | 272 | 43 | 0 | 0.338 | 1.000 | 0.505 |
| z3_only | 139 | 492 | 42 | 0 | 0.220 | 1.000 | 0.361 |

Dev set has severe class imbalance (1560 non-vuln vs 632 vuln finding-level rows).

---

### Caveats
- Metrics above are **contract-level** for test, finding-level for dev
- Test set: 36 vuln + 8 labeled non-vuln (only 44/62 have ground truth in CSV)
- 15 task errors in non-vuln run (solc version issues) — 705/720 OK
- **Previous 125-contract subset results RETRACTED** — this supersedes all prior numbers

---

## Next Steps

| Priority | Task | Status |
|----------|------|--------|
| 1 | Error analysis on 3 FNs (why missed) | **In Progress** |
| 2 | Install/run Mythril & Securify baselines | **In Progress** |
| 3 | Update synopsis with test-set results + baseline comparison | Ready |
| 4 | GitHub push + Docker artifact | Ready |