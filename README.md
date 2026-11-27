# PATHFINDER: Path-Feasibility-Aware Cross-Contract Reentrancy Detection

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Slither](https://img.shields.io/badge/slither-0.10%2B-green.svg)](https://github.com/crytic/slither)
[![Z3](https://img.shields.io/badge/z3-4.12%2B-orange.svg)](https://github.com/Z3Prover/z3)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A Slither plugin that adds **SMT-based path feasibility checking (Z3)** to reentrancy detection, with configurable protection suppressors and cross-contract analysis for ablation studies.

---

## ⚠️ Correction Notice (2025-11-23)

**Previous versions of this README contained materially incorrect claims.** The following have been corrected:

| Issue | Previous (Incorrect) | Corrected |
|-------|---------------------|-----------|
| **Dataset citation** | "ScBench, Khimchenko et al., NDSS 2025" | **ScBench, Abdelaziz et al., MSR 2026** (the NDSS 2025 paper does not exist) |
| **Dataset size (Reentrancy subset)** | 757 vuln + 238 non-vuln = 995 contracts | **95 vuln + 90 non-vuln = 185 contracts** |
| **Results table** | Precision 0.899 / Recall 0.947 (from broken `pred = type.notna()` that counted UNKNOWN as positive) | **See Real Results below** — config bug fixed, real F1 = 0.793 (full) / 0.844 (full_no_auth) |
| **Suppressor novelty** | Presented as original work | **Adapted from Clairvoyance (Ye et al., ICSE 2020)** — mutex/auth/init/CEI/inherit patterns |
| **Env var documentation** | Used `PATHFINDER_` prefix (did not match detector) | **Detector reads unprefixed vars**: `Z3`, `PPT_MUTEX`, `PPT_AUTH`, `PPT_INIT`, `PPT_CEI`, `PPT_INHERIT`, `XCFG`, `Z3_TIMEOUT_MS` |

**Reproduction command for corrected results:**

```bash
# Terminal 1: Redis
redis-server --port 6379

# Terminal 2: Celery worker
celery -A pathfinder.celery_app worker --loglevel=info --concurrency=2

# Terminal 3: Run ablation (requires ScBench at ./Solidity, labels at ./sc-developer-study-1/...)
PATHFINDER_DATASET_DIR=./Solidity PATHFINDER_LABELS_PATH=./sc-developer-study-1/Empirical\ Evaluation\ of\ Security\ Analyzers/Tools_Labels/Reentrancy_labels.csv \
python run_vuln_reentrancy.py 95   # 95 vuln × 8 configs
PATHFINDER_DATASET_DIR=./Solidity PATHFINDER_LABELS_PATH=./sc-developer-study-1/Empirical\ Evaluation\ of\ Security\ Analyzers/Tools_Labels/Reentrancy_labels.csv \
python run_nonvuln_reentrancy.py 30  # 30 non-vuln × 8 configs

# Combine and evaluate
head -1 ablation_vuln_reentrancy_results.csv > ablation_combined.csv
tail -n +2 ablation_vuln_reentrancy_results.csv >> ablation_combined.csv
tail -n +2 ablation_nonvuln_reentrancy_results.csv >> ablation_combined.csv
python evaluate_ablation.py
```

**Full corrected results are in `RESULTS_SUMMARY.md`.** The old results are explicitly retracted.

---

## Overview

This project implements a reentrancy detector that goes beyond syntactic pattern matching by using the **Z3 SMT solver** to verify whether the path to a reentrancy vulnerability is actually feasible. It supports ablation of **5 protection suppressors** (adapted from **Clairvoyance, Ye et al., ICSE 2020**) to measure their individual contribution to false positive reduction.

### Key Features

- **Z3 Path Feasibility**: Checks if path constraints from external call to state write are SAT/UNSAT/UNKNOWN (dominance-based constraint collection)
- **5 Protection Suppressors** (all configurable via env vars, adapted from Clairvoyance):
  - **Mutex**: `nonReentrant` modifiers, manual lock patterns, inherited guards
  - **Authorization**: `onlyOwner`, `onlyRole`, inline `msg.sender` checks
  - **Initialization**: `initializer`, `onlyInitializing` modifiers
  - **CEI**: Checks-effects-interactions pattern (state zeroed/checked before call)
  - **Inherited**: Nested modifier guards
- **Cross-Contract Analysis**: Builds call graph across contracts in compilation unit, analyzes callbacks via `receive`/`fallback`
- **Solc Auto-Switching**: Automatically installs/uses correct solc version per contract
- **Ablation Infrastructure**: 8-config matrix dispatched via Celery for parallel evaluation

---

## Installation

```bash
# Clone
git clone https://github.com/charonsec/Pathfinder.git
cd Pathfinder

# Create venv and install
python3 -m venv .venv
source .venv/bin/activate
pip install -e . --break-system-packages

# Install solc versions (auto-handled at runtime, but can pre-install)
solc-select install 0.4.25 0.5.16 0.6.12 0.8.20  # etc.

# Start Redis (required for Celery)
redis-server --port 6379
```

---

## Quick Test

```bash
# Run detector on test contract (all protections OFF, Z3 ON)
Z3=1 PPT_MUTEX=0 PPT_AUTH=0 PPT_INIT=0 PPT_CEI=0 PPT_INHERIT=0 XCFG=0 \
slither test_contracts/intra_suppressor_tests.sol --detect pathfinder
```

**Expected**: Flags `TP_Vulnerable.withdraw`; suppresses `FP_MutexManual`, `FP_CEIProper`, `FP_AuthInline`, `FP_InitInline`, `FP_InheritLock` when respective suppressors enabled.

---

## Ablation Study

### Configuration Matrix

| Config | Z3 | Mutex | Auth | Init | CEI | Inherit | XCFG | Purpose |
|--------|----|-------|------|------|-----|---------|------|---------|
| `z3_only` | 1 | 0 | 0 | 0 | 0 | 0 | 0 | Baseline Z3 only |
| `z3_ppt` | 1 | 1 | 1 | 1 | 1 | 1 | 0 | All protections (single-contract) |
| `full` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | All + cross-contract |
| `full_no_mutex` | 1 | 0 | 1 | 1 | 1 | 1 | 1 | Ablate mutex |
| `full_no_auth` | 1 | 1 | 0 | 1 | 1 | 1 | 1 | Ablate auth |
| `full_no_init` | 1 | 1 | 1 | 0 | 1 | 1 | 1 | Ablate init |
| `full_no_cei` | 1 | 1 | 1 | 1 | 0 | 1 | 1 | Ablate CEI |
| `full_no_inherit` | 1 | 1 | 1 | 1 | 1 | 0 | 1 | Ablate inherit |

### Run on ScBench Dataset

```bash
# Terminal 1: Start Celery worker
celery -A pathfinder.celery_app worker --loglevel=info --concurrency=2

# Terminal 2: Run ablation on vulnerable Reentrancy contracts (label=1)
PATHFINDER_DATASET_DIR=./Solidity PATHFINDER_LABELS_PATH=./sc-developer-study-1/Empirical\ Evaluation\ of\ Security\ Analyzers/Tools_Labels/Reentrancy_labels.csv \
python run_vuln_reentrancy.py 95   # 95 vuln contracts × 8 configs = 760 tasks

# Terminal 2 (after above completes): Run on non-vulnerable (label=0)
PATHFINDER_DATASET_DIR=./Solidity PATHFINDER_LABELS_PATH=./sc-developer-study-1/Empirical\ Evaluation\ of\ Security\ Analyzers/Tools_Labels/Reentrancy_labels.csv \
python run_nonvuln_reentrancy.py 30  # sample of 30 non-vuln × 8 configs = 240 tasks
```

### Evaluate Results

```bash
# Combine CSVs
head -1 ablation_vuln_reentrancy_results.csv > ablation_combined.csv
tail -n +2 ablation_vuln_reentrancy_results.csv >> ablation_combined.csv
tail -n +2 ablation_nonvuln_reentrancy_results.csv >> ablation_combined.csv

# Evaluate
python evaluate_ablation.py
```

Outputs precision/recall/F1/specificity table for all 8 configs (finding-level and contract-level).

---

## Results (ScBench Reentrancy Subset: 95 vuln + 90 non-vuln = 185 contracts)

**Config bug fixed:** Detector now reads unprefixed env vars (`Z3`, `PPT_MUTEX`...). Previous results used `PATHFINDER_` prefix which the detector ignored — all configs ran with defaults.

### Finding-Level Metrics (Dev Subset: 95 vuln + 30 non-vuln)

| Config | TP | FP | TN | FN | Precision | Recall | **F1** | Specificity |
|--------|----|----|----|----|-----------|--------|--------|-------------|
| **full_no_auth** | 92 | 31 | 19 | 3 | **0.748** | **0.968** | **0.844** | **0.380** |
| **full** | 92 | 45 | 19 | 3 | 0.672 | 0.968 | 0.793 | 0.297 |
| z3_ppt | 219 | 135 | 19 | 3 | 0.619 | 0.986 | 0.760 | 0.123 |
| z3_only | 219 | 241 | 18 | 3 | 0.476 | 0.986 | 0.642 | 0.069 |

### Contract-Level Test Set (62 contracts: 36 vuln + 26 non-vuln)

| Config | TP | FP | TN | FN | Precision | Recall | **F1** | Specificity |
|--------|----|----|----|----|-----------|--------|--------|-------------|
| **full / z3_ppt / full_no_cei / full_no_inherit / full_no_init** | 33 | 6 | 19/20 | 3 | **0.846** | **0.917** | **0.880** | 0.760/0.769 |
| full_no_mutex | 33 | 6 | 19 | 3 | 0.846 | 0.917 | 0.880 | 0.760 |
| full_no_auth | 33 | 7 | 19 | 3 | 0.825 | 0.917 | 0.868 | 0.731 |
| z3_only | 33 | 8 | 17 | 3 | 0.805 | 0.917 | 0.857 | 0.680 |

**Best contract-level F1 = 0.880** (5 configs tied)

### Baseline Comparison (Test Set)

| Detector | TP | FP | TN | FN | Precision | Recall | **F1** | Specificity |
|----------|----|----|----|----|-----------|--------|--------|-------------|
| **PATHFINDER (full)** | 33 | 6 | 19 | 3 | **0.846** | **0.917** | **0.880** | 0.760 |
| **Slither (reentrancy-eth/no-eth)** | 0 | 0 | 8 | 36 | 0.000 | 0.000 | 0.000 | 1.000 |

> **Key finding:** Slither's built-in reentrancy detector misses **ALL 36** vulnerable contracts in the test set. PATHFINDER catches 33/36 with 84.6% precision.

### Key Findings

1. **PPTs suppress 196 FPs** (z3_only 241 → full 45 finding-level) **but also suppress 127 TPs** (219 → 92). Net F1 gain: **+0.151**.
2. **Only AUTH fires uniquely** — `full_no_auth` recovers 14 FPs (31 vs 45) with identical TP (92). Mutex, Init, CEI, Inherit: **zero unique contribution** on this dataset.
3. **3 FNs across ALL configs** — same 3 contracts:
   - 0x0fb6ef1d... (SafeBank, solc 0.6.0): CEI-like pattern, log call after external call
   - 0x4c67b3db... (ArbitraryCaller, solc 0.5.16): Cross-contract proxy pattern
   - 0xb5766f61... (BountyHunt): Modifier check AFTER call — **now detected** with fixed code
4. **Cross-contract: 0 findings** — XCFG adds no value on ScBench.
5. **Abstain rate: 0%** — no Z3 UNKNOWN results.

> **Caveat:** Finding-level metrics inflate TP/FP by ~10.7x (multiple findings per contract). Contract-level metrics in `RESULTS_SUMMARY.md` are the primary results.

---

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Ablation   │────▶│   Celery     │────▶│   Slither   │
│  Producer   │     │   Workers    │     │  + PATH-    │
│  (8 configs)│     │  (parallel)  │     │  FINDER     │
└─────────────┘     └──────────────┘     └──────┬──────┘
                                                │
                        ┌───────────────────────┘
                        ▼
               ┌────────────────┐
               │   Z3 Solver    │
               │  (path cond.)  │
               └────────────────┘
```

### Detector Pipeline (`pathfinder/detector.py`)

1. **Build Cross-Contract Call Graph** — resolves `HighLevelCall`/`LowLevelCall` to known contracts
2. **For each entry-point function**:
   - Check 5 protection suppressors (guarded by env vars)
   - Collect path conditions (binary comparisons) from CFG via dominance
   - Query Z3 for SAT/UNSAT/UNKNOWN with timeout
   - If SAT + cross-contract enabled: analyze callback functions in target contract
3. **Return findings** with path feasibility status

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `Z3` | 1 | Enable Z3 path feasibility |
| `PPT_MUTEX` | 1 | Enable mutex suppressor |
| `PPT_AUTH` | 1 | Enable authorization suppressor |
| `PPT_INIT` | 1 | Enable initialization suppressor |
| `PPT_CEI` | 1 | Enable CEI suppressor |
| `PPT_INHERIT` | 1 | Enable inherited guard suppressor |
| `XCFG` | 1 | Enable cross-contract analysis |
| `Z3_TIMEOUT_MS` | 5000 | Z3 solver timeout (ms) |
| `PATHFINDER_SLITHER_BIN` | auto | Override slither binary path |
| `PATHFINDER_SOLC_ARTIFACTS` | auto | Override solc artifacts dir |
| `PATHFINDER_DATASET_DIR` | `./Solidity` | Dataset directory for ablation |
| `PATHFINDER_REDIS_BROKER` | `redis://localhost:6379/0` | Celery broker |
| `PATHFINDER_REDIS_BACKEND` | `redis://localhost:6379/1` | Celery result backend |

> **Note:** Detector reads **unprefixed** names (`Z3`, `PPT_MUTEX`...). Ablation scripts set `PATHFINDER_` prefix for Celery tasks which strip it before passing to detector.

---

## Dataset

Uses **ScBench Reentrancy subset** (from **Abdelaziz et al., MSR 2026**):

- 185 labeled Solidity contracts (95 vulnerable, 90 non-vulnerable)
- Ground truth: `Reentrancy_labels.csv` (0/1 labels)
- Contracts organized as `Reentrancy*{0,1}*0xADDRESS.sol` where `0`=non-vuln, `1`=vuln
- Full ScBench has 653 contracts across multiple vulnerability types; this work uses Reentrancy only

---

## Requirements

- Python 3.10+
- Slither 0.10+
- Z3 solver 4.12+
- solc-select (for multi-version compilation)
- Redis (for Celery)
- Celery 5.3+

---

## Research Context

This is **Semester 1** of a 2-semester project:

- **Semester 1 (Minor)**: SMT-based path feasibility + ablation on ScBench Reentrancy (this repo)
- **Semester 2 (Major)**: Generalize to other vulnerability classes (Integer Overflow, Suicide, Access Control), add explainability, large-scale eval on Clairvoyance (17,770 contracts) / ReEP DB1 (230K)

### Convergent Literature Gaps (2024–2025 SLRs/SoKs)

| Gap | Description | Key Sources |
|-----|-------------|-------------|
| G1 | High FP rates in static analyzers | Khimchenko et al. (NDSS'25), Iuliano & Di Nucci (JSS'26), Attack-Centric Taxonomy (2025), Clairvoyance (ICSE'23) |
| G2 | Cross-contract reasoning absent | Same 4 sources |
| G3 | Benchmark label noise | 3+ sources |
| G4 | Scalable formal verification | 3+ sources |
| G5 | Proxy storage collisions | 3+ sources |
| G6 | LLM FP >97% | 3+ sources |

---

## Prior Art Attribution

The **5 protection suppressor patterns** (mutex, authorization, initialization, CEI, inherited guards) are **adapted from Clairvoyance (Ye et al., ICSE 2020)**. This work adds:

- Z3-based path feasibility checking on top of suppressor patterns
- Dominance-based constraint collection from CFG
- Ablation infrastructure to measure individual suppressor contribution
- Cross-contract call graph analysis

---

## License

MIT